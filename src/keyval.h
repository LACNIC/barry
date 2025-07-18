#ifndef SRC_KEYVAL_H_
#define SRC_KEYVAL_H_

#include <sys/queue.h>

enum kv_type {
	VALT_STR,
	VALT_ARRAY,
};

struct kv_node {
	char *value;
	STAILQ_ENTRY(kv_node) hook;
};

struct kv_value {
	enum kv_type type;
	union {
		char *str;
		STAILQ_HEAD(kv_list, kv_node) list;
		char *src;
	} v;
};

struct keyval {
	char *key;
	struct kv_value val;

	STAILQ_ENTRY(keyval) hook;
};

STAILQ_HEAD(keyvals, keyval);

#endif /* SRC_KEYVAL_H_ */
