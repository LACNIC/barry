#ifndef SRC_STR_H_
#define SRC_STR_H_

#include <stdbool.h>
#include <stddef.h>

char *concat(char const *, char const *);
bool str_has_suffix(char const *, char const *);
char *path_join(char const *, char const *);

int str2ul(char const *, char const *, unsigned long, unsigned long *);

struct dynamic_string {
	char *buf;
	size_t len;
	size_t size;
};

void dstr_append(struct dynamic_string *, char const *, ...);
char *dstr_finish(struct dynamic_string *);
void dstr_cleanup(struct dynamic_string *);

#endif /* SRC_STR_H_ */
