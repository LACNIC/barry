#ifndef SRC_CER_H_
#define SRC_CER_H_

#include <libasn1fort/Certificate.h>
#include <openssl/evp.h>

#include "ext.h"
#include "rpki_tree.h"
#include "rpp.h"

struct rpki_certificate {
	struct rpki_object *meta;
	struct rpp rpp;
	EVP_PKEY *keys;

#define SPKI obj.tbsCertificate.subjectPublicKeyInfo
	Certificate_t obj;
	struct extensions exts;

	struct field *objf;
	struct field *rppf;
};

struct rpki_certificate *cer_new(struct rpki_tree_node *, enum cer_type);
void cer_init(struct rpki_certificate *, struct rpki_object *, enum cer_type);
void cer_finish_rpp(struct rpki_certificate *);
void cer_finish_ta(struct rpki_certificate *);
void cer_finish_ca(struct rpki_certificate *);
void cer_finish_ee(struct rpki_certificate *, struct rpki_object *);
void cer_write(struct rpki_certificate *);

struct rpki_certificate *cer_parent(struct rpki_certificate *);
char const *cer_rpkiManifest(struct rpki_certificate *);
char const *cer_cdp(struct rpki_certificate *);
struct ext_list_node *cer_ext(struct rpki_certificate *, enum ext_type);

#endif /* SRC_CER_H_ */
