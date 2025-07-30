#ifndef SRC_CER_H_
#define SRC_CER_H_

#include <openssl/evp.h>
#include <libasn1fort/Certificate.h>
#include <libasn1fort/SubjectKeyIdentifier.h>

#include "ext.h"
#include "field.h"
#include "rpki_tree.h"
#include "rpp.h"

extern const struct field_template cer_metadata[];

struct rpki_certificate {
	char *uri;
	char *path;
	struct rpp rpp;

	struct rpki_certificate *parent;
	struct field *fields; /* Hash table */

	char const *subject;
	EVP_PKEY *keys;
	SubjectPublicKeyInfo_t *spki;

	Certificate_t obj;
	struct extensions exts;
};

struct rpki_certificate *cer_new(char const *,
    struct rpki_certificate *, enum cer_type);
void cer_init(struct rpki_certificate *, struct field **, char const *,
    struct rpki_certificate *, enum cer_type, char const *);
void cer_generate_paths(struct rpki_certificate *, char const *);
void cer_apply_keyvals(struct rpki_certificate *, struct keyvals *);
void cer_finish_ta(struct rpki_certificate *);
void cer_finish_ca(struct rpki_certificate *);
void cer_finish_ee(struct rpki_certificate *, char const *);
void cer_write(struct rpki_certificate *cer);
void cer_print(struct rpki_certificate *cer);

#endif /* SRC_CER_H_ */
