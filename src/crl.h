#ifndef SRC_CRL_H_
#define SRC_CRL_H_

#include <libasn1fort/CertificateList.h>

#include "cer.h"

struct rpki_crl {
	char *uri;
	char *path;

	struct rpki_certificate *parent;
	struct field *fields; /* Hash table */

	CertificateList_t obj;
	struct extensions exts;
};

struct rpki_crl *crl_new(struct rpki_certificate *);
void crl_generate_paths(struct rpki_crl *, char const *);
void crl_apply_keyvals(struct rpki_crl *, struct keyvals *);
void crl_finish(struct rpki_crl *);
void crl_write(struct rpki_crl *);
void crl_print(struct rpki_crl *);

#endif /* SRC_CRL_H_ */
