#ifndef SRC_FIELD_H_
#define SRC_FIELD_H_

#include <stdbool.h>
#include "keyval.h"
#include "uthash.h"

typedef char const *error_msg;
typedef error_msg (*field_parser)(struct kv_value *, void *);
typedef void (*print_field)(void *);

struct field_type {
	char const *name;
	field_parser parser;
	print_field print;
};

struct field {
	char const *key;
	struct field_type const *type;
	size_t offset;
	/*
	 * This is two things in one:
	 * 1. If nonzero, the field is a pointer. Otherwise not a pointer.
	 * 2. If nonzero, it's the number of bytes that need to be allocated
	 *    if the field needs to exist.
	 */
	size_t size;
	struct field const *children;

	/* Internal */
	UT_hash_handle hh;
};

extern const struct field_type ft_int;
extern const struct field_type ft_oid;
extern const struct field_type ft_8str;
extern const struct field_type ft_any;
extern const struct field_type ft_bitstr;
extern const struct field_type ft_name;
extern const struct field_type ft_time;
extern const struct field_type ft_gtime;
extern const struct field_type ft_ip_roa;
extern const struct field_type ft_ip_cer;
extern const struct field_type ft_asn_cer;
extern const struct field_type ft_revoked;

extern const struct field algorithm_metadata[];

void fields_compile(struct field const *, struct field **);
struct field *fields_find(struct field *, char const *);
void fields_apply_keyvals(struct field *, void *, struct keyvals *);
void fields_print(struct field const *, void *);

#endif /* SRC_FIELD_H_ */
