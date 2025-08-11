#include "csv.h"

#include <stdbool.h>
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

void
csv_print3(struct rpki_object *cell1, char const *cell2, char const *cell3)
{
	csv_print(cell1->name, ',');
	csv_print(cell2, ',');
	csv_print(cell3, '\n');
}
