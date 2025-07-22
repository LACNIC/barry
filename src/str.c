#include "str.h"

#include <stdlib.h>
#include "print.h"

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
dstr_append(struct dynamic_string *str, unsigned char const *addend,
    size_t addlen)
{
	size_t total;

	total = str->len + addlen;
	if (total > str->size) {
		str->size = next_power_of_2(total);
		str->buf = realloc(str->buf, str->size);
		if (!str->buf)
			enomem;
	}

	memcpy(str->buf + str->len, addend, addlen);
	str->len += addlen;
}
