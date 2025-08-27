#ifndef SRC_MFT_H_
#define SRC_MFT_H_

#include "so.h"

struct signed_object *mft_new(struct rpki_tree_node *);
void mft_finish(struct signed_object *, struct rpki_tree_node *);
void mft_write(struct signed_object *);

#endif /* SRC_MFT_H_ */
