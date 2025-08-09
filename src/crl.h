#ifndef SRC_CRL_H_
#define SRC_CRL_H_

#include <libasn1fort/CertificateList.h>

#include "cer.h"

struct rpki_crl {
	struct rpki_object *meta;

	CertificateList_t obj;
	struct extensions exts;
};

struct rpki_crl *crl_new(struct rpki_object *);
void crl_generate_paths(struct rpki_crl *);
void crl_finish(struct rpki_crl *);
void crl_write(struct rpki_crl *);
void crl_print(struct rpki_crl *);

#endif /* SRC_CRL_H_ */
