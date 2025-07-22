#include "crl.h"

#include <stdbool.h>
#include <libasn1fort/CRLNumber.h>
#include <libasn1fort/Extension.h>
#include <libasn1fort/SignatureValue.h>

#include "alloc.h"
#include "asn1.h"
#include "ext.h"
#include "libcrypto.h"
#include "oid.h"

const struct field crl_metadata[] = {
	{
		"tbsCertList.version",
		&ft_int,
		offsetof(struct rpki_crl, obj.tbsCertList.version),
		sizeof(Version_t),
	}, {
		"tbsCertList.signature",
		NULL,
		offsetof(struct rpki_crl, obj.tbsCertList.signature),
		0,
		algorithm_metadata,
	}, {
		"tbsCertList.issuer",
		&ft_name,
		offsetof(struct rpki_crl, obj.tbsCertList.issuer),
	}, {
		"tbsCertList.thisUpdate",
		&ft_time,
		offsetof(struct rpki_crl, obj.tbsCertList.thisUpdate),
	}, {
		"tbsCertList.nextUpdate",
		&ft_time,
		offsetof(struct rpki_crl, obj.tbsCertList.nextUpdate),
		sizeof(struct Time),
	}, {
		"tbsCertList.revokedCertificates",
		&ft_revoked,
		offsetof(struct rpki_crl, obj.tbsCertList.revokedCertificates),
		sizeof(struct TBSCertList__revokedCertificates),
	},
	/* { tbsCertList.crlExtensions } */
	{
		"signatureAlgorithm",
		NULL,
		offsetof(struct rpki_crl, obj.signatureAlgorithm),
		0,
		algorithm_metadata,
	}, {
		"signature",
		&ft_bitstr,
		offsetof(struct rpki_crl, obj.signature),
	},
	{ 0 }
};

static struct field *crl_fields;

static void
init_extensions_crl(struct rpki_crl *crl)
{
	Extensions_t *exts;
	AuthorityKeyIdentifier_t aki = { 0 };
	CRLNumber_t crln = { 0 };

	pr_debug("- Initializing CRL extensions");

	exts = pzalloc(sizeof(struct Extensions));
	crl->obj.tbsCertList.crlExtensions = exts;
	INIT_ASN1_ARRAY(&exts->list, 2, Extension_t);

	/* AKI */
	init_aki(&aki, crl->parent->spki);
	init_ext(exts->list.array[0], &asn_DEF_AuthorityKeyIdentifier, NID_authority_key_identifier, false, &aki);

	/* CRL Number */
	init_INTEGER(&crln, 1);
	init_ext(exts->list.array[1], &asn_DEF_CRLNumber, NID_crl_number, false, &crln);
}

static void
update_signature(CertificateList_t *crl, EVP_PKEY *privkey)
{
	unsigned char der[4096];
	asn_enc_rval_t rval;
	SignatureValue_t signature;

	pr_debug("- Signing");

	rval = der_encode_to_buffer(&asn_DEF_TBSCertList,
	    &crl->tbsCertList, der, sizeof(der));
	if (rval.encoded < 0)
		panic("TBSCertList rval.encoded: %zd", rval.encoded);

	signature = do_sign(privkey, der, rval.encoded);
	crl->signature.buf = signature.buf;
	crl->signature.size = signature.size;
}


struct rpki_crl *
crl_new(struct rpki_certificate *parent)
{
	struct rpki_crl *crl;
	TBSCertList_t *tbs;

	crl = pzalloc(sizeof(struct rpki_crl));

	tbs = &crl->obj.tbsCertList;
	tbs->version = intmax2INTEGER(1);
	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	/* issuer: Postpone (needs parent's subject) */
	init_time_now(&tbs->thisUpdate);
	tbs->nextUpdate = pzalloc(sizeof(Time_t)); // TODO Needs to be nullable
	init_time_later(tbs->nextUpdate);

	/* tbs->extensions: Not implemented yet */
	init_oid(&crl->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	crl->obj.signatureAlgorithm.parameters = create_null();
	/* crl->signature: Postpone (needs all other fields ready) */

	crl->parent = parent; // TODO check NULL?
	return crl;
}

void
crl_generate_paths(struct rpki_crl *crl, char const *filename)
{
	crl->uri = generate_uri(crl->parent, filename);
	pr_debug("- uri: %s", crl->uri);

	crl->path = generate_path(crl->parent, filename);
	pr_debug("- path: %s", crl->path);

	crl->parent->rpp.crldp = crl->uri;
}

static void
ensure_compiled(void)
{
	if (!crl_fields)
		fields_compile(crl_metadata, &crl_fields);
}

void
crl_apply_keyvals(struct rpki_crl *crl, struct keyvals *kvs)
{
	ensure_compiled();
	fields_apply_keyvals(crl_fields, crl, kvs);
}

void
crl_finish(struct rpki_crl *crl)
{
	if (crl->obj.tbsCertList.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&crl->obj.tbsCertList.issuer, crl->parent->subject);
	}
	init_extensions_crl(crl);
	update_signature(&crl->obj, crl->parent->keys);
}

void
crl_write(struct rpki_crl *crl)
{
	asn1_write(crl->path, &asn_DEF_CertificateList, &crl->obj);
}

void
crl_print(struct rpki_crl *crl)
{
	printf("- Type: CRL\n");
	printf("- URI : %s\n", crl->uri);
	printf("- Path: %s\n", crl->path);

	ensure_compiled();
	fields_print(crl_fields, crl);
}
