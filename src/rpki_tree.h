#ifndef SRC_RPKI_TREE_H_
#define SRC_RPKI_TREE_H_

#include <stdbool.h>
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

struct rpki_tree {
	/* Array; all nodes, listed without hierarchy */
	struct rpki_tree_node *nodes;
	/* Nodes in tree form */
	struct rpki_tree_node *root;
};

struct rpki_tree rpkitree_load(char const *);

void
rpkitree_pre_order(
    struct rpki_tree *tree,
    void (*cb)(struct rpki_tree *, struct rpki_tree_node *, void *),
    void *arg
);

void rpkitree_add(
    struct rpki_tree *,
    struct rpki_tree_node *,
    struct rpki_tree_node *
);

void rpkitree_print(struct rpki_tree *);

#endif /* SRC_RPKI_TREE_H_ */
