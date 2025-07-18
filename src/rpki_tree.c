#include "rpki_tree.h"

void
rpkitree_pre_order(
    struct rpki_tree_node *root,
    void (*cb)(struct rpki_tree_node *, void *),
    void *arg
) {
	struct rpki_tree_node *child, *tmp;

	if (root == NULL)
		return;
	cb(root, arg);

	// TODO ditch recursion
	HASH_ITER(phook, root->children, child, tmp)
		rpkitree_pre_order(child, cb, arg);
}
