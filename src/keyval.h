#ifndef SRC_KEYVAL_H_
#define SRC_KEYVAL_H_

#include <sys/queue.h>

/*
 * Somewhat annoying naming:
 *
 * - "keyval"s are the user's overrides.
 * - "field"s (field.h) are ASN1 object metadata.
 */

enum kv_type {
	VALT_STR,
	VALT_SET,
	VALT_MAP,
};

struct keyval;
STAILQ_HEAD(keyvals, keyval);

struct kv_value {
	enum kv_type type;
	union {
		char *str;
		STAILQ_HEAD(kv_set, kv_node) set;
		struct keyvals map;
	} v;
};

struct kv_node {
	struct kv_value value;
	STAILQ_ENTRY(kv_node) hook;
};

struct keyval {
	char *key;
	struct kv_value value;
	STAILQ_ENTRY(keyval) hook;
};

struct kv_value *keyvals_find(struct keyvals *, char const *);

#endif /* SRC_KEYVAL_H_ */
