#ifndef SRC_FIELD_H_
#define SRC_FIELD_H_

#include <libasn1fort/AccessDescription.h>
#include <libasn1fort/AlgorithmIdentifier.h>
#include <libasn1fort/FileAndHash.h>
#include <libasn1fort/GeneralName.h>
#include <libasn1fort/Name.h>
#include <libasn1fort/SubjectPublicKeyInfo.h>
#include <stdbool.h>

#include "keyval.h"
#include "str.h"
#include "uthash.h"

#define FIELD_MAXLEN 128 // XXX

struct field;

typedef char const *error_msg;
typedef error_msg (*field_parser)(struct field *, struct kv_value *, void *);
typedef void (*print_field)(struct dynamic_string *, void *);

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

	struct field *parent;
	/* Tree children (hash table) */
	struct field *children;
	/* Parent's hash table hook */
	UT_hash_handle hh;
};

extern const struct field_type ft_obj;
extern const struct field_type ft_bool;
extern const struct field_type ft_int;
extern const struct field_type ft_oid;
extern const struct field_type ft_8str;		/* octet string */
extern const struct field_type ft_utf8str;
extern const struct field_type ft_ia5str;
extern const struct field_type ft_anystr;
extern const struct field_type ft_cstr;		/* char * */
extern const struct field_type ft_any;
extern const struct field_type ft_any_oid;
extern const struct field_type ft_bitstr;
extern const struct field_type ft_rdnseq;
extern const struct field_type ft_gname_type;	/* GeneralName type */
extern const struct field_type ft_time;
extern const struct field_type ft_gtime;	/* GeneralizedTime */
extern const struct field_type ft_filetype;
extern const struct field_type ft_exts;
extern const struct field_type ft_ads;		/* AccessDescriptions array */
extern const struct field_type ft_ip_roa;
extern const struct field_type ft_ip_cer;
extern const struct field_type ft_asn_cer;
extern const struct field_type ft_revoked;
extern const struct field_type ft_filelist;
extern const struct field_type ft_providers;
extern const struct field_type ft_files;

struct field *field_add(struct field *, char const *, struct field_type const *,
    void *, size_t);
struct field *field_addn(struct field *, size_t, struct field_type const *,
    void *, size_t);
struct field *field_add_name(struct field *, char const *, Name_t *);
struct field *field_add_gname(struct field *, char const *, GeneralName_t *);
struct field *field_add_algorithm(struct field *, char const *,
    AlgorithmIdentifier_t *);
struct field *field_add_spki(struct field *, char const *,
    SubjectPublicKeyInfo_t *);
void field_add_file(struct field *, size_t, struct FileAndHash *, bool, bool);
struct field *field_add_ad(struct field *, size_t, AccessDescription_t *);

struct field *fields_find(struct field *, char const *);
struct field *fields_find_n(struct field *, size_t);
bool fields_overridden(struct field *, char const *);

error_msg fields_apply_keyvals(struct field *, struct keyvals *);
void fields_print_md(struct field const *);
void fields_print_csv(struct field const *, char const *);

#endif /* SRC_FIELD_H_ */
