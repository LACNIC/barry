#ifndef SRC_STR_H_
#define SRC_STR_H_

#include <stddef.h>

char *concat(char const *, char const *);

struct dynamic_string {
	char *buf;
	size_t len;
	size_t size;
};

void dstr_append(struct dynamic_string *, char const *, ...);
char *dstr_finish(struct dynamic_string *);
void dstr_cleanup(struct dynamic_string *);

#endif /* SRC_STR_H_ */
