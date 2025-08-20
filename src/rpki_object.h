#ifndef SRC_RPKI_OBJECT_H_
#define SRC_RPKI_OBJECT_H_

struct rpki_certificate;
struct rpki_tree;
struct field;

struct rpki_object {
	char *uri;
	char *path;
	char *name;

	struct rpki_tree *tree;
	struct rpki_certificate *parent;

	/* All the tweakable fields in the object */
	struct field *fields;
};

void meta_print_csv(struct rpki_object *);

#endif /* SRC_RPKI_OBJECT_H_ */
