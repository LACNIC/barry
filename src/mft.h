#ifndef SRC_MFT_H_
#define SRC_MFT_H_

#include <libasn1fort/Manifest.h>
#include "cer.h"
#include "keyval.h"
#include "rpki_tree.h"
#include "so.h"

struct signed_object *mft_new(struct rpki_tree_node *);
void mft_finish(struct signed_object *, struct rpki_tree_node *);
void mft_write(struct signed_object *);

#endif /* SRC_MFT_H_ */
