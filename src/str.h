#ifndef SRC_STR_H_
#define SRC_STR_H_

#include <string.h>

struct dynamic_string {
	char *buf;
	size_t len;
	size_t size;
};

void dstr_append(struct dynamic_string *, unsigned char const *, size_t);

#endif /* SRC_STR_H_ */
