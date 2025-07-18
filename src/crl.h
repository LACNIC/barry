#ifndef SRC_CRL_H_
#define SRC_CRL_H_

#include <libasn1fort/CertificateList.h>

#include "cer.h"

extern const struct field crl_metadata[];

struct rpki_crl {
	char *uri;
	char *path;

	CertificateList_t obj;
	struct rpki_certificate *parent;
};

struct rpki_crl *crl_new(struct rpki_certificate *);
void crl_generate_paths(struct rpki_crl *, char const *);
void crl_apply_keyvals(struct rpki_crl *, struct keyvals *);
void crl_finish(struct rpki_crl *);
void crl_write(struct rpki_crl *);
void crl_print(struct rpki_crl *);

#endif /* SRC_CRL_H_ */
