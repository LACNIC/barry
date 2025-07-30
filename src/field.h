#ifndef SRC_FIELD_H_
#define SRC_FIELD_H_

#include <stdbool.h>
#include "keyval.h"
#include "uthash.h"

#define FIELD_MAXLEN 128 // XXX

struct field;

typedef char const *error_msg;
typedef error_msg (*field_parser)(struct field *, char const *,
    struct kv_value *, void *);
typedef void (*print_field)(void *);

struct field_type {
	char const *name;
	field_parser parser;
	print_field print;
};

struct field_template {
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
	struct field_template const *children;
};

struct field {
	char *key;
	struct field_type const *type;
	void *address;
	size_t size;		/* Same as field_template.size */
	bool overridden;
	bool invisible;

	/* Internal */
	UT_hash_handle hh;
};

extern const struct field_type ft_bool;
extern const struct field_type ft_int;
extern const struct field_type ft_oid;
extern const struct field_type ft_8str;
extern const struct field_type ft_any;
extern const struct field_type ft_bitstr;
extern const struct field_type ft_name;
extern const struct field_type ft_time;
extern const struct field_type ft_gtime;
extern const struct field_type ft_exts;
extern const struct field_type ft_ip_roa;
extern const struct field_type ft_ip_cer;
extern const struct field_type ft_asn_cer;
extern const struct field_type ft_revoked;

extern const struct field_template algorithm_metadata[];

void fields_compile(struct field_template const *, char const *, void *,
    struct field **);
void fields_add(struct field *, char const *,
    struct field_type const *, void *, size_t, bool);
void fields_add_ext(struct field *,
    char const *, char const *, size_t, char const *,
    struct field_type const *, void *, size_t);
void fields_remove(struct field *, char const *);

struct field *fields_find(struct field *, char const *);
bool fields_ext_set(struct field *, char const *,
    char const *, unsigned int,
    char const *);

void fields_apply_keyvals(struct field *, void *, struct keyvals *);
void fields_print(struct field const *);

#endif /* SRC_FIELD_H_ */
