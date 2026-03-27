#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "print.h"

#define OPTLONG_VERBOSE		"verbose"
#define OPTLONG_HELP		"help"

static char const *old_path;
static char const *new_path;
unsigned int verbosity;
bool print_colors;

static void
print_help(void)
{
	printf("Usage: barry-mtim [-hv [-v]] <old-path> <new-path>\n");
	printf("\n");
	printf("Given that <new-path> contains a more recent version of <old-path>,\n");
	printf("copies the modification times of all the files that didn't change\n");
	printf("between the transition from <old-path> to <new-path>.\n");
}

static void
parse_options(int argc, char **argv)
{
	static struct option opts[] = {
		{ OPTLONG_VERBOSE,              no_argument,       0, 'v' },
		{ OPTLONG_HELP,                 no_argument,       0, 'h' },
		{ 0 }
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "vh", opts, NULL)) != -1) {
		switch (opt) {
		case 'v':	verbosity++;		break;
		case 'h':	print_help();		exit(EXIT_SUCCESS);
		case '?':	print_help();		exit(EXIT_FAILURE);
		}
	}

	if (argc - optind < 1) {
		fprintf(stderr, "Missing <old-path> and <new-path>.\n");
		goto fail;
	}
	old_path = argv[optind];

	if (argc - optind < 2) {
		fprintf(stderr, "Missing <new-path>.\n");
		goto fail;
	}
	new_path = argv[optind + 1];

	pr_debug("Configuration:");
	pr_debug("   --" OPTLONG_VERBOSE " = %u", verbosity);
	pr_debug("   old path  = %s", old_path);
	pr_debug("   new path  = %s", new_path);
	pr_debug("");
	return;

fail:	print_help();
	exit(EXIT_FAILURE);
}

struct queued_file {
	char *path;
	STAILQ_ENTRY(queued_file) lh;
};

STAILQ_HEAD(queued_files, queued_file) queue;

static void
queue_path(struct queued_files *queue, char const *path)
{
	struct queued_file *qfile;

	qfile = pmalloc(sizeof(struct queued_file));
	qfile->path = pstrdup(path);
	STAILQ_INSERT_TAIL(queue, qfile, lh);
}

static bool
is_dots(char const *str)
{
	return str[0] == '.' && (str[1] == 0 || (str[1] == '.' && str[2] == 0));
}

char const *
skip_prefix(char const *str, char const *pfx)
{
	while (pfx[0] != 0) {
		if (str[0] != pfx[0])
			return NULL;
		str++;
		pfx++;
	}

	return str;
}

char *
path_join(char const *str1, char const *str2)
{
	char *str3;
	size_t len3;
	int ret;

	len3 = strlen(str1) + strlen(str2) + 2;
	str3 = pmalloc(len3);

	ret = snprintf(str3, len3, "%s/%s", str1, str2);
	if (ret < 0 || len3 <= ret)
		panic("snprintf(%s, %s): %d", str1, str2, ret);

	return str3;
}

/* Not thread-safe! */
bool
diff(char const *path1, char const *path2)
{
	static char buf1[4096], buf2[4096];
	int file1, file2;
	ssize_t read1, read2;
	int error;

	file1 = open(path1, O_RDONLY, 0);
	if (file1 < 0) {
		error = errno;
		if (error == ENOENT)
			return true;
		panic("open(%s): %s", path1, strerror(error));
	}
	file2 = open(path2, O_RDONLY, 0);
	if (file2 < 0)
		panic("open(%s): %s", path2, strerror(errno));

	do {
		read1 = read(file1, buf1, 4096);
		if (read1 < 0)
			panic("read(%s): %s", path1, strerror(errno));
		read2 = read(file2, buf2, 4096);
		if (read2 < 0)
			panic("read(%s): %s", path2, strerror(errno));

		if (read1 == 0 && read2 == 0) {
			close(file1);
			close(file2);
			return false;
		} else if (read1 == 0 || read2 == 0) {
			break;
		} else if (read1 == read2) {
			if (memcmp(buf1, buf2, read1) != 0)
				break;
		} else if (read1 < read2) {
			if (memcmp(buf1, buf2, read1) != 0)
				break;
			memmove(buf2, buf2 + read1, read2 - read1);
		} else {
			if (memcmp(buf1, buf2, read2) != 0)
				break;
			memmove(buf1, buf1 + read2, read1 - read2);
		}
	} while (true);

	close(file1);
	close(file2);
	return true;
}

static void
update_date(char const *new_file)
{
	char const *subpath;
	char *old_file;
	struct stat st1;
	struct timespec times[2];

	subpath = skip_prefix(new_file, new_path);
	if (!subpath)
		panic("'%s' does not start with '%s'.", new_file, new_path);

	old_file = path_join(old_path, subpath);

	if (!diff(old_file, new_file)) {
		pr_trace("Rolling back modification time of %s.", new_file);

		if (stat(old_file, &st1) < 0)
			panic("stat(%s): %s", old_file, strerror(errno));

#if defined(__APPLE__)
		times[0] = st1.st_atimespec;
		times[1] = st1.st_mtimespec;
#else
		times[0] = st1.st_atim;
		times[1] = st1.st_mtim;
#endif

		if (utimensat(AT_FDCWD, new_file, times, AT_SYMLINK_NOFOLLOW) < 0)
			panic("utimensat(%s): %s", new_file, strerror(errno));
	}

	free(old_file);
}

int
main(int argc, char **argv)
{
	struct queued_file *qfile;
	DIR *dir;
	struct dirent *file;
	char *filepath;
	struct stat st;

	parse_options(argc, argv);

	STAILQ_INIT(&queue);
	queue_path(&queue, new_path);

	do {
		qfile = STAILQ_FIRST(&queue);

		dir = opendir(qfile->path);
		if (!dir) {
			if (errno == ENOENT)
				goto next;
			panic("opendir(%s): %s", qfile->path, strerror(errno));
		}

		for (errno = 0, file = readdir(dir); file; errno = 0, file = readdir(dir)) {
			if (is_dots(file->d_name))
				continue;

			filepath = path_join(qfile->path, file->d_name);

			if (lstat(filepath, &st) < 0)
				panic("stat(%s): %s", filepath, strerror(errno));
			if (S_ISREG(st.st_mode))
				update_date(filepath);
			else if (S_ISDIR(st.st_mode))
				queue_path(&queue, filepath);

			free(filepath);
		}

		if (errno)
			panic("readdir(%s): %s", qfile->path, strerror(errno));
		closedir(dir);

next:		STAILQ_REMOVE_HEAD(&queue, lh);
		free(qfile->path);
		free(qfile);
	} while (!STAILQ_EMPTY(&queue));

	return EXIT_SUCCESS;
}
