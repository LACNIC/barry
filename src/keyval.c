#include "keyval.h"

#include <stddef.h>
#include <string.h>

/* Note: O(n). If you use this too much, probably hash table keyvals. */
struct kv_value *
keyvals_find(struct keyvals *kvs, char const *key)
{
	struct keyval *kv;
	struct kv_value *result;

	/* Dupes allowed; last one takes precedence */

	result = NULL;
	STAILQ_FOREACH(kv, kvs, hook)
		if (strcmp(kv->key, key) == 0)
			result = &kv->value;
	return result;
}
