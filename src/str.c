#include "str.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "alloc.h"
#include "print.h"

char *
concat(char const *s1, char const *s2)
{
	size_t len1, len2;
	char *result;

	len1 = strlen(s1);
	len2 = strlen(s2);

	result = pmalloc(len1 + len2 + 1);
	strcpy(result, s1);
	strcpy(result + len1, s2);
	return result;
}

bool
str_has_suffix(char const *str, char const *suffix)
{
	size_t str_len;
	size_t suffix_len;

	str_len = strlen(str);
	suffix_len = strlen(suffix);
	if (str_len < suffix_len)
		return false;

	return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
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

static bool
is_whitespace(char c)
{
	/*
	 * Note: Needs to be consistent with next_token().
	 * (Plus null character)
	 */
	return c == ' '  || c == 0    || c == '\t' || c == '\n'
	    || c == '\r' || c == '\v' || c == '\f';
}

int
str2ul(char const *what, char const *str, unsigned long max, unsigned long *ul)
{
	unsigned long v;
	char *tailptr;
	int base;

	if (!str) {
		pr_err("Expected token after '%s'.", what);
		return EINVAL;
	}

	if (str[0] == '0' && str[1] == 'x') {
		base = 16;
		str += 2;
	} else if (str[0] == '0' && str[1] == 'b') {
		base = 2;
		str += 2;
	} else {
		base = 10;
	}

	errno = 0;
	v = strtoul(str, &tailptr, base);
	if (errno) {
		pr_err("Cannot convert %s to int: %s", what, strerror(errno));
		return EINVAL;
	}
	if (str == tailptr) {
		pr_err("Cannot convert %s to int.", what);
		return EINVAL;
	}
	if (!is_whitespace(*tailptr)) {
		pr_err("Number has suffix garbage: %s", str);
		return EINVAL;
	}
	if (v > max) {
		pr_err("%s cannot be > %lu.", what, max);
		return EINVAL;
	}

	*ul = v;
	return 0;
}

static size_t
next_power_of_2(size_t src)
{
	size_t power = 1;

	/*
	 * Notice: Unprotected from overflow.
	 * We need to be able to test long strings, so I'm trusting the user
	 * will not shoot themself in the foot.
	 */

	while (power < src)
		power <<= 1;
	return power;
}

void
dstr_append(struct dynamic_string *str, char const *fmt, ...)
{
	size_t capacity;
	int wlen;
	va_list ap;

	capacity = str->size - str->len;

	va_start(ap, fmt);
	wlen = vsnprintf(str->buf + str->len, capacity, fmt, ap);
	va_end(ap);

	if (wlen < 0)
		panic("vsnprintf(1): %d", wlen);
	if (wlen < capacity) {
		str->len += wlen;
		return;
	}

	str->size = str->len + wlen + 1;
	str->size = next_power_of_2(str->size);
	str->buf = realloc(str->buf, str->size);
	if (!str->buf)
		enomem;

	capacity = str->size - str->len;

	va_start(ap, fmt);
	wlen = vsnprintf(str->buf + str->len, capacity, fmt, ap);
	va_end(ap);

	if (wlen < 0 || capacity <= wlen)
		panic("vsnprintf(2): %d", wlen);

	str->len += wlen;
}

char *
dstr_finish(struct dynamic_string *str)
{
	return str->buf;
}

void
dstr_cleanup(struct dynamic_string *str)
{
	free(str->buf);
}
