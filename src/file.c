#include "file.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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

	strncpy(result, base, nbase);
	result[nbase] = '/';
	strncpy(result + nbase + 1, filename, nfilename);
	result[nresult -1] = '\0';

	return result;
}

char *
remove_extension(char const *filename)
{
	char const *dot = strchr(filename, '.');
	return dot ? pstrndup(filename, dot - filename) : pstrdup(filename);
}

/* Does not care if the path already exists. */
void
exec_mkdir(char *path)
{
	pr_trace("mkdir '%s'", path);
	if (mkdir(path, 0750) < 0 && errno != EEXIST)
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
