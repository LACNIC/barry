#ifndef SRC_TAL_H_
#define SRC_TAL_H_

#include "cer.h"

char *tal_autogenerate_path(char const *);
void tal_write(struct rpki_certificate *, char const *path);

#endif /* SRC_TAL_H_ */
