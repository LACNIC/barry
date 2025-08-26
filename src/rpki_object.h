#ifndef SRC_RPKI_OBJECT_H_
#define SRC_RPKI_OBJECT_H_

struct rpki_tree;
struct rpki_tree_node;
struct rpki_certificate;

struct rpki_object {
	char *uri;
	char *path;
	char *name;

	struct rpki_tree *tree;
	struct rpki_tree_node *node;
};

struct rpki_certificate *meta_parent(struct rpki_object *);

#endif /* SRC_RPKI_OBJECT_H_ */
