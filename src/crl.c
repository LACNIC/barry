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

const struct field_template crl_metadata[] = {
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

static char const *EXT_CTX = "tbsCertList.crlExtensions";

static void
init_extensions_crl(struct rpki_crl *crl)
{
	size_t n;

	pr_debug("- Initializing CRL extensions");

	INIT_ASN1_ARRAY(&crl->exts.array.list, 2, Extension_t);
	STAILQ_INIT(&crl->exts.list);

	n = 0;
	exts_add_aki(&crl->exts, n++, crl->fields, EXT_CTX);
	exts_add_crln(&crl->exts, n++, crl->fields, EXT_CTX);
}

struct rpki_crl *
crl_new(struct rpki_certificate *parent)
{
	struct rpki_crl *crl;
	TBSCertList_t *tbs;

	crl = pzalloc(sizeof(struct rpki_crl));
	crl->parent = parent; // TODO check NULL?
	fields_compile(crl_metadata, NULL, crl, &crl->fields);

	tbs = &crl->obj.tbsCertList;
	tbs->version = intmax2INTEGER(1);
	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	/* issuer: Postpone (needs parent's subject) */
	init_time_now(&tbs->thisUpdate);
	tbs->nextUpdate = pzalloc(sizeof(Time_t)); // TODO Needs to be nullable
	init_time_later(tbs->nextUpdate);
	/* revokedCertificates: TODO not implemented yet */
	crl->obj.tbsCertList.crlExtensions = &crl->exts.array;
	init_oid(&crl->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	crl->obj.signatureAlgorithm.parameters = create_null();
	/* crl->signature: Postpone (needs all other fields ready) */

	init_extensions_crl(crl);

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

void
crl_apply_keyvals(struct rpki_crl *crl, struct keyvals *kvs)
{
	fields_apply_keyvals(crl->fields, crl, kvs);
}

static void
update_signature(CertificateList_t *crl, EVP_PKEY *privkey)
{
	unsigned char der[4096];
	asn_enc_rval_t rval;
	SignatureValue_t signature;

	// TODO autocomputed even if overridden

	pr_debug("- Signing");

	rval = der_encode_to_buffer(&asn_DEF_TBSCertList,
	    &crl->tbsCertList, der, sizeof(der));
	if (rval.encoded < 0)
		panic("TBSCertList rval.encoded: %zd", rval.encoded);

	signature = do_sign(privkey, der, rval.encoded);
	crl->signature.buf = signature.buf;
	crl->signature.size = signature.size;
}

static bool
is_field_set(struct rpki_crl *crl, char const *name,
    unsigned int extn, char const *suffix)
{
	return fields_ext_set(crl->fields, EXT_CTX, name, extn, suffix);
}

static void
finish_extensions(struct rpki_crl *crl)
{
	struct ext_list_node *ext;
	unsigned int extn;

	extn = 0;
	STAILQ_FOREACH(ext, &crl->exts.list, hook) {
		if (ext->type == EXT_AKI) {
			if (!is_field_set(crl, "aki", extn, "extnValue.keyIdentifier")) {
				if (!crl->parent)
					panic("CRL needs a default AKI, but lacks a parent");
				finish_aki(&ext->v.aki, crl->parent->spki);
			}
		}

		extn++;
	}

	extn = 0;
	STAILQ_FOREACH(ext, &crl->exts.list, hook)
		der_encode_8str(ext->td, &ext->v, &crl->exts.array.list.array[extn++]->extnValue);
}

void
crl_finish(struct rpki_crl *crl)
{
	if (crl->obj.tbsCertList.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&crl->obj.tbsCertList.issuer, crl->parent->subject);
	}
	finish_extensions(crl);
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

	fields_print(crl->fields);
}
