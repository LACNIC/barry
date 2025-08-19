#ifndef SRC_ALLOC_H_
#define SRC_ALLOC_H_

#include <stdlib.h>

/* The 'p' stands for "panicky." */

void *pmalloc(size_t);
void *pzalloc(size_t);
void *pcalloc(size_t, size_t);
char *pstrdup(char const *);
void psnprintf(char *, size_t, char const *, ...);

#endif /* SRC_ALLOC_H_ */
