#include "alloc.h"

#include <stdarg.h>
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

	result = calloc(1, size);
	if (!result)
		enomem;

	return result;
}

void *
pcalloc(size_t n, size_t size)
{
	void *result;

	result = calloc(n, size);
	if (!result)
		enomem;

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

char *
pstrndup(char const *s, size_t size)
{
	char *result;

	result = strndup(s, size);
	if (!result)
		enomem;

	return result;
}

void
psnprintf(char *buf, size_t size, char const *tpl, ...)
{
	va_list ap;
	int chars;

	va_start(ap, tpl);
	chars = vsnprintf(buf, size, tpl, ap);
	va_end(ap);

	if (chars < 0 || size <= chars)
		panic("vsnprintf(): %d", chars);
}
