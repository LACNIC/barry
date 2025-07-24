#ifndef SRC_KEYVAL_H_
#define SRC_KEYVAL_H_

#include <sys/queue.h>

enum kv_type {
	VALT_STR,
	VALT_SET,
	VALT_MAP,
};

struct kv_value {
	enum kv_type type;
	union {
		char *str;
		STAILQ_HEAD(kv_set, kv_node) set;
		STAILQ_HEAD(kv_map, keyval) map;
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

STAILQ_HEAD(keyvals, keyval);

#endif /* SRC_KEYVAL_H_ */
