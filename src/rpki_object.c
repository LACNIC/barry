#include "rpki_object.h"

#include "cer.h"
#include "print.h"
#include "so.h"

struct rpki_certificate *
meta_certificate(struct rpki_object *meta)
{
	struct rpki_tree_node *node;

	node = meta->node;
	if (IS_CER(node->type))
		return node->obj;
	if (IS_SO(node->type))
		return &((struct signed_object *)(node->obj))->ee;
	return NULL;
}

struct rpki_certificate *
meta_parent(struct rpki_object *meta)
{
	struct rpki_tree_node *parent;

	parent = meta->node->parent;
	return parent ? meta_certificate(&parent->meta) : NULL;
}
