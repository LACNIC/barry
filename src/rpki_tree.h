#ifndef SRC_RPKI_TREE_H_
#define SRC_RPKI_TREE_H_

#include "keyval.h"
#include "uthash.h"

enum file_type {
	FT_UNKNOWN = 0,

	FT_TA,
	FT_CER,
	FT_CRL,
	FT_MFT,
	FT_ROA,
};

struct rpki_tree_node {
	char *name;
	enum file_type type;
	unsigned int indent;
	struct keyvals props;
	void *obj;

	struct rpki_tree_node *parent;
	struct rpki_tree_node *children; /* Hash table */

	UT_hash_handle phook; /* Parent hash table hook */
	UT_hash_handle ghook; /* Global hash table hook */
};

void
rpkitree_pre_order(
    struct rpki_tree_node *root,
    void (*cb)(struct rpki_tree_node *, void *),
    void *arg
);

#endif /* SRC_RPKI_TREE_H_ */
