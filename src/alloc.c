#include "alloc.h"

#include <string.h>

#include "print.h"

void *
pmalloc(size_t size)
{
	void *result;

	result = malloc(size);
	if (!result)
		enomem;

	return result;
}

void *
pzalloc(size_t size)
{
	void *result;

	result = pmalloc(size);
	memset(result, 0, size);

	return result;
}

char *
pstrdup(char const *s)
{
	char *result;

	result = strdup(s);
	if (!result)
		enomem;

	return result;
}
