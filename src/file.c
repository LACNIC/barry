#define _XOPEN_SOURCE 500

#include "file.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "print.h"

/*
 * filename doesn't have to be a single component; you can join
 * base="a/b/c" with filename="d/e/f" just fine.
 */
char *
join_paths(char const *base, char const *filename)
{
	size_t nbase, nfilename, nresult;
	char *result;

	nbase = strlen(base);
	nfilename = strlen(filename);

	if (base[nbase - 1] == '/')
		nbase--;
	if (filename[0] == '/') {
		filename++;
		nfilename--;
	}

	nresult = nbase + nfilename + 2;
	result = pmalloc(nresult);

	memcpy(result, base, nbase);
	result[nbase] = '/';
	memcpy(result + nbase + 1, filename, nfilename);
	result[nresult -1] = '\0';

	return result;
}

char *
remove_extension(char const *filename)
{
	char const *dot = strrchr(filename, '.');
	return dot ? pstrndup(filename, dot - filename) : pstrdup(filename);
}

int
write_open(char const *path)
{
	int fd;

	exec_mkdir_p(path, false);

	pr_trace("echo 'Beep boop' > %s", path);
	fd = creat(path, 0644);
	if (fd < 0)
		panic("creat(%s): %s", path, strerror(errno));

	return fd;
}

/* Does not care if the path already exists. */
void
exec_mkdir(char *path)
{
	pr_trace("mkdir '%s'", path);
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		panic("mkdir(%s): %s", path, strerror(errno));
}

/* Does not care if the path already exists, automatically creates parents. */
void
exec_mkdir_p(char const *_path, bool include_last)
{
	char *path, *slash;

	if (_path == NULL)
		panic("Path is NULL.");
	if (_path[0] == '\0')
		panic("Path is empty.");

	path = pstrdup(_path);
	slash = path;

	while ((slash = strchr(slash + 1, '/')) != NULL) {
		*slash = '\0';
		exec_mkdir(path);
		*slash = '/';
	};

	if (include_last)
		exec_mkdir(path);

	free(path);
}

static int
rm(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	if (remove(fpath) < 0)
		panic("Cannot remove %s: %s", fpath, strerror(errno));
	return 0;
}

static void
rm_rf(char const *path)
{
	int error;

	if (nftw(path, rm, 32, FTW_DEPTH | FTW_PHYS) >= 0)
		return; /* Happy path */

	error = errno;
	if (error == ENOTDIR) {
		/* This can happen in MacOS; try file removal. */
		if (unlink(path) == 0)
			return; /* Rare happy path */
		error = errno;
	}

	panic("Cannot remove %s: %s", path, strerror(error));
}

static bool
is_dots(char const *file)
{
	return (file[0] == '.' && file[1] == 0)
	    || (file[0] == '.' && file[1] == '.' && file[2] == 0);
}

/*
 * Removes @path's content (excludes @path itself).
 * Not thread-safe.
 */
void
exec_rm_rf_content(char const *path)
{
	DIR *dir;
	struct dirent *file;
	char *subpath;
	int error;

	if (!path)
		return;

	pr_trace("rm -rf %s/*", path);

	dir = opendir(path);
	if (dir == NULL) {
		error = errno;
		if (error != ENOENT)
			panic("Cannot open %s: %s", path, strerror(error));

		pr_trace("Nonexistent directory.");
		return;
	}

	for (errno = 0, file = readdir(dir); file; errno = 0, file = readdir(dir))
		if (!is_dots(file->d_name)) {
			subpath = join_paths(path, file->d_name);
			/* XXX looks like there's a Fort error here */
			rm_rf(subpath);
			free(subpath);
		}

	error = errno;
	if (error)
		panic("%s traversal interrupted: %s", path, strerror(error));

	closedir(dir);
	pr_trace("Directory removed.");
}
