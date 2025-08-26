#include "rpki_object.h"

#include "print.h"
#include "rpki_tree.h"

struct rpki_certificate *
meta_parent(struct rpki_object *meta)
{
	struct rpki_tree_node *parent;

	parent = meta->node->parent;
	if (parent == NULL)
		return NULL;
	if (parent->type != FT_TA && parent->type != FT_CER)
		panic("%s's parent is not a certificate.", meta->name);
	return parent->obj;
}
