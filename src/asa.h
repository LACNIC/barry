#ifndef SRC_ASA_H_
#define SRC_ASA_H_

#include "so.h"

struct signed_object *asa_new(struct rpki_tree_node *);
void asa_finish(struct signed_object *);
void asa_write(struct signed_object *);

#endif /* SRC_ASA_H_ */
