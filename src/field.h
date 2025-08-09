#ifndef SRC_FIELD_H_
#define SRC_FIELD_H_

#include <stdbool.h>
#include <libasn1fort/AlgorithmIdentifier.h>
#include <libasn1fort/SubjectPublicKeyInfo.h>

#include "keyval.h"
#include "uthash.h"

#define FIELD_MAXLEN 128 // XXX

struct field;

typedef char const *error_msg;
typedef error_msg (*field_parser)(struct field *, struct kv_value *, void *);
typedef void (*print_field)(void *);

struct field_type {
	char const *name;
	field_parser parser;
	print_field print;
};

struct field {
	/* AKA. "name" */
	char const *key;
	struct field_type const *type;
	/* Memory location of the field's value */
	void *address;
	/*
	 * This is two things in one:
	 * 1. If nonzero, the field is a pointer. Otherwise not a pointer.
	 * 2. If nonzero, it's the number of bytes that need to be allocated
	 *    if the field needs to exist.
	 */
	size_t size;
	/* Value already applied to @address? */
	bool overridden;
	/* Hide field during print? */
	bool invisible;

	/* Tree children (hash table) */
	struct field *children;
	/* Parent's hash table hook */
	UT_hash_handle hh;
};

extern const struct field_type ft_bool;
extern const struct field_type ft_int;
extern const struct field_type ft_oid;
extern const struct field_type ft_8str;		/* octet string */
extern const struct field_type ft_any;
extern const struct field_type ft_bitstr;
extern const struct field_type ft_name;
extern const struct field_type ft_time;
extern const struct field_type ft_gtime;	/* generalized time */
extern const struct field_type ft_exts;
extern const struct field_type ft_ip_roa;
extern const struct field_type ft_ip_cer;
extern const struct field_type ft_asn_cer;
extern const struct field_type ft_revoked;

struct field *field_add_static(struct field *, char const *);
struct field *field_add_static_n(struct field *, size_t);
struct field *field_add(struct field *, char const *, struct field_type const *,
    void *, size_t);
struct field *field_add_algorithm(struct field *, char const *,
    AlgorithmIdentifier_t *);
struct field *field_add_spki(struct field *, char const *,
    SubjectPublicKeyInfo_t *);

struct field *fields_find(struct field *, char const *);

void fields_apply_keyvals(struct field *, void *, struct keyvals *);
void fields_print(struct field const *);

#endif /* SRC_FIELD_H_ */
