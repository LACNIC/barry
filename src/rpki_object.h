#ifndef SRC_RPKI_OBJECT_H_
#define SRC_RPKI_OBJECT_H_

struct rpki_certificate;
struct field;

struct rpki_object {
	char *uri;
	char *path;
	char *name;

	struct rpki_certificate *parent;

	/* All the tweakable fields in the object */
	struct field *fields;
};

#endif /* SRC_RPKI_OBJECT_H_ */
