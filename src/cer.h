#ifndef SRC_CER_H_
#define SRC_CER_H_

#include <openssl/evp.h>
#include <libasn1fort/Certificate.h>
#include <libasn1fort/SubjectKeyIdentifier.h>

#include "ext.h"
#include "field.h"
#include "rpki_tree.h"
#include "rpp.h"

struct rpki_certificate {
	struct rpki_object *meta;

	struct rpp rpp;

	EVP_PKEY *keys;
	SubjectPublicKeyInfo_t *spki;

	Certificate_t obj;
	struct extensions exts;
};

struct rpki_certificate *cer_new(struct rpki_object *, enum cer_type);
void cer_init(struct rpki_certificate *, struct rpki_object *, enum cer_type);
void cer_generate_paths(struct rpki_certificate *);
void cer_finish_ta(struct rpki_certificate *);
void cer_finish_ca(struct rpki_certificate *);
void cer_finish_ee(struct rpki_certificate *, char const *);
void cer_write(struct rpki_certificate *cer);
void cer_print_md(struct rpki_certificate *cer);
void cer_print_csv(struct rpki_certificate *cer);

#endif /* SRC_CER_H_ */
