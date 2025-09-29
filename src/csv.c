#include "csv.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

void
csv_print(char const *value, char separator)
{
	char const *quote;

	if (value == NULL) {
		printf("%c", separator);
		return;
	}

	if (!strchr(value, ',')) {
		printf("%s%c", value, separator);
		return;
	}

	printf("\"");
	while ((quote = strchr(value, '"')) != NULL) {
		printf("%.*s", (int)(quote - value), value);
		printf("\"\"");
		value = quote + 1;
	}

	printf("%s\"%c", value, separator);
}
