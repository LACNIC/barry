#ifndef SRC_RPKI_TREE_H_
#define SRC_RPKI_TREE_H_

#include <stdbool.h>
#include <libasn1fort/UTF8String.h>

#include "field.h"
#include "keyval.h"
#include "rpki_object.h"
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
	struct rpki_object meta;

	enum file_type type;
	void *obj;

	/* Overrides by the user */
	struct keyvals props;

	/* For tree building */
	unsigned int indent;
	struct rpki_tree_node *parent;
	/* Hash table */
	struct rpki_tree_node *children;

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

	struct {
		char *uri;
		char *path;
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

struct rrdp_notification *notif_getsert(struct rpki_tree *, char const *);
void notif_add_file(struct rrdp_notification *, char *);
void __notif_add_file(char const *, struct rrdp_files *, char *);

#endif /* SRC_RPKI_TREE_H_ */
