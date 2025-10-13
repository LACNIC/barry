#ifndef SRC_RPKI_TREE_H_
#define SRC_RPKI_TREE_H_

#include "field.h"
#include "rpki_object.h"

enum file_type {
	FT_UNKNOWN = 0,

	FT_TA,
	FT_CER,
	FT_CRL,
	FT_MFT,
	FT_ROA,
};

struct rpki_tree_node {
	struct rpki_object meta;

	enum file_type type;
	void *obj;

	/* All the tweakable fields in the object */
	struct field *fields;
	/* Overrides by the user */
	struct keyvals props;

	unsigned int indent;	/* Only for tree building */
	struct rpki_tree_node *parent;
	/* Hash table */
	struct rpki_tree_node *children;
	unsigned int depth;	/* aka. ancestor count */
	unsigned int serial;	/* This node is parent's `serial`th child */

	/* Parent hash table hook */
	UT_hash_handle phook;
	/* Global hash table hook */
	UT_hash_handle ghook;
};

struct rrdp_file {
	char *name;
	STAILQ_ENTRY(rrdp_file) hook;
};

struct rrdp_notification {
	char *uri;
	char *path;
	char *session;
	INTEGER_t serial;

	struct {
		char *uri;
		char *path;
		char *session;
		INTEGER_t *serial;
		STAILQ_HEAD(rrdp_files, rrdp_file) files;
	} snapshot;

	/* All the tweakable fields in the object */
	struct field *fields; /* TODO why is this a pointer? */
	/* Overrides by the user */
	struct keyvals props;

	UT_hash_handle hh;
};

struct rpki_tree {
	/* Linked hash table; all nodes, listed without hierarchy */
	struct rpki_tree_node *nodes;
	/* Nodes in tree form. Pointer to root node; not a hash table. */
	struct rpki_tree_node *root;
	/* RRDP notifications hash table */
	struct rrdp_notification *notifications;
};

void rpkitree_load(char const *, struct rpki_tree *);

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

struct rrdp_notification *notif_getsert(struct rpki_tree *, char *);
void notif_add_file(struct rrdp_notification *, char *);
void __notif_add_file(char const *, struct rrdp_files *, char *);

#endif /* SRC_RPKI_TREE_H_ */
