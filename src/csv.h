#ifndef SRC_CSV_H_
#define SRC_CSV_H_

#include "rpki_object.h"

void csv_print(char const *, char separator);
void csv_print3(struct rpki_object *, char const *, char const *);

#endif /* SRC_CSV_H_ */
