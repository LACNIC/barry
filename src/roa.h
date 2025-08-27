#ifndef SRC_ROA_H_
#define SRC_ROA_H_

#include "so.h"

struct signed_object *roa_new(struct rpki_tree_node *);
void roa_finish(struct signed_object *);
void roa_write(struct signed_object *);

#endif /* SRC_ROA_H_ */
