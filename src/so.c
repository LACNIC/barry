#include "so.h"

#include <libasn1fort/ANY.h>
#include <libasn1fort/CMSAttributeValue.h>
#include <libasn1fort/DigestAlgorithmIdentifier.h>
#include <libasn1fort/SignerInfo.h>

#include "asn1.h"
#include "crl.h"
#include "libcrypto.h"
#include "oid.h"

const struct field signer_info_metadata[] = {
	{
		"version",
		&ft_int,
		offsetof(SignerInfo_t, version)
	}, {
		"sid.issuerAndSerialNumber.issuer",
		&ft_name,
		offsetof(SignerInfo_t, sid.choice.issuerAndSerialNumber.issuer)
	}, {
		"sid.issuerAndSerialNumber.serialNumber",
		&ft_int,
		offsetof(SignerInfo_t, sid.choice.issuerAndSerialNumber.serialNumber)
	}, {
		"sid.subjectKeyIdentifier",
		&ft_8str,
		offsetof(SignerInfo_t, sid.choice.subjectKeyIdentifier)
	}, {
		"digestAlgorithm",
		NULL,
		offsetof(SignerInfo_t, digestAlgorithm),
		false,
		algorithm_metadata
	},
	/* { "signedAttrs" }, */
	{
		"signatureAlgorithm",
		NULL,
		offsetof(SignerInfo_t, signatureAlgorithm),
		false,
		algorithm_metadata
	}, {
		"signature",
		&ft_8str,
		offsetof(SignerInfo_t, signature)
	},
	/* { "unsignedAttrs" }, */
	{ 0 }
};

const struct field so_metadata[] = {
	{
		"contentType",
		&ft_oid,
		offsetof(struct signed_object, ci.contentType)
	}, {
		"content.version",
		&ft_int,
		offsetof(struct signed_object, sd.version)
	}, /* {
		"content.digestAlgorithms[0]",
		NULL,
		offsetof(struct signed_object, sd.digestAlgorithms),
		false,
		algorithm_metadata
	}, */ {
		"content.encapContentInfo.eContentType",
		&ft_oid,
		offsetof(struct signed_object, sd.encapContentInfo.eContentType)
	},
	/* Type-specific fields here */
	{
		"content.certificates[0]",
		NULL,
		offsetof(struct signed_object, ee),
		0,
		cer_metadata,
	},
	/* { "content.crls[0].crl", NULL, offsetof(struct signed_object, crl), crl_metadata }, */
	{
		"content.signerInfos[0]",
		NULL,
		offsetof(struct signed_object, si),
		false,
		signer_info_metadata
	},
	{ 0 }
};

static void
init_content_info(ContentInfo_t *ci)
{
	init_oid(&ci->contentType, NID_pkcs7_signed);
}

static void
sign_so(SignatureValue_t *signature, EVP_PKEY *privkey, SignedAttributes_t *attrs)
{
	unsigned char der[4096];
	asn_enc_rval_t rval;

	rval = der_encode_to_buffer(&asn_DEF_SignedAttributes, attrs,
	    der, sizeof(der));
	if (rval.encoded < 0)
		panic("SignedAttributes rval.encoded: %zd", rval.encoded);

	der[0] = 0x31;
	*signature = do_sign(privkey, der, rval.encoded);
}

/* Requires the EE ready and eContentS */
static void
finish_signer_info(SignerInfo_t *si, struct rpki_certificate *ee,
    OCTET_STRING_t *eContent)
{
	CMSAttribute_t *attr;
	OCTET_STRING_t md = { 0 };

	if (si->sid.present == SignerIdentifier_PR_NOTHING) {
		pr_debug("- Copying the EE SKI to the SignerInfo");
		si->sid.present = SignerIdentifier_PR_subjectKeyIdentifier;
		si->sid.choice.subjectKeyIdentifier = ee->ski;
	}

	attr = si->signedAttrs->list.array[1];
	if (attr->attrValues.list.count == 0) {
		pr_debug("- Hashing the eContent into the Message-Digest CMSAttribute");
		init_oid(&attr->attrType, NID_pkcs9_messageDigest);
		INIT_ASN1_ARRAY(&attr->attrValues.list, 1, CMSAttributeValue_t);
		hash_sha256(eContent->buf, eContent->size, &md);
		der_encode_any(&asn_DEF_OCTET_STRING, &md,
		    attr->attrValues.list.array[0]);
	}

	if (si->signature.buf == NULL) {
		pr_debug("- Signing");
		sign_so(&si->signature, ee->keys, si->signedAttrs);
	}
}

/* Needs the SO _t, and the EE _t. */
static void
finish_signed_data(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	SignedData_t *sd = &so->sd;

	/* Needs the SO _t */
	pr_debug("- Encoding the eContent");
	sd->encapContentInfo.eContent = pzalloc(sizeof(OCTET_STRING_t));
	der_encode_8str(td, &so->obj, sd->encapContentInfo.eContent);
	/* eContent (DER) ready */

	/* Needs the EE _t */
	pr_debug("- Encoding the EE");
	der_encode_any(&asn_DEF_Certificate, &so->ee.obj,
	    sd->certificates->list.array[0]);

	/* Needs the EE and eContent (DER) */
	finish_signer_info(&so->si, &so->ee, so->sd.encapContentInfo.eContent);
}

static void
finish_content_info(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	finish_signed_data(so, td);
	pr_debug("- Encoding the SignedData into the ContentInfo");
	der_encode_any(&asn_DEF_SignedData, &so->sd, &so->ci.content);
}

static void
init_signer_info(SignerInfo_t *si, /* struct entity *ee, OCTET_STRING_t *eContent,
    EVP_PKEY *sign_key, */ int nid)
{
	CMSAttribute_t *attr;
	OBJECT_IDENTIFIER_t ct;
	Time_t st = { 0 };

	init_INTEGER(&si->version, 3);

	/* ski postponed */

	init_oid(&si->digestAlgorithm.algorithm, NID_sha256);

	si->signedAttrs = pzalloc(sizeof(SignedAttributes_t));
	INIT_ASN1_ARRAY(&si->signedAttrs->list, 3, CMSAttribute_t);

	attr = si->signedAttrs->list.array[0];
	init_oid(&attr->attrType, NID_pkcs9_contentType);
	INIT_ASN1_ARRAY(&attr->attrValues.list, 1, CMSAttributeValue_t);
	init_oid(&ct, nid);
	der_encode_any(&asn_DEF_OBJECT_IDENTIFIER, &ct, attr->attrValues.list.array[0]);

	/* signedAttrs[1] postponed */

	attr = si->signedAttrs->list.array[2];
	init_oid(&attr->attrType, NID_pkcs9_signingTime);
	INIT_ASN1_ARRAY(&attr->attrValues.list, 1, CMSAttributeValue_t);
	init_time_now(&st);
	der_encode_any(&asn_DEF_Time, &st, attr->attrValues.list.array[0]);

	init_oid(&si->signatureAlgorithm.algorithm, NID_rsaEncryption);
}

static void
init_signed_data(struct signed_object *so, int nid)
{
	SignedData_t *sd = &so->sd;
	DigestAlgorithmIdentifier_t *dai;

	init_INTEGER(&sd->version, 3);

	INIT_ASN1_ARRAY(&sd->digestAlgorithms.list, 1, DigestAlgorithmIdentifier_t);
	dai = (DigestAlgorithmIdentifier_t *)sd->digestAlgorithms.list.array[0];
	init_oid(&dai->algorithm, NID_sha256);

	init_oid(&sd->encapContentInfo.eContentType, nid);
	/* eContent postponed */

	sd->certificates = pzalloc(sizeof(struct CertificateSet));
	INIT_ASN1_ARRAY(&sd->certificates->list, 1, ANY_t);

	/* crls not implemented yet */

	INIT_ASN1_ARRAY(&sd->signerInfos.list, 1, SignerInfo_t);
	sd->signerInfos.list.array[0] = &so->si;
}

struct signed_object *
signed_object_new(char const *filename, struct rpki_certificate *parent,
    int nid)
{
	struct signed_object *so;

	so = pzalloc(sizeof(struct signed_object));

	init_content_info(&so->ci);
	init_signed_data(so, nid);
	so->parent = parent;
	cer_init(&so->ee, filename, parent);
	init_signer_info(&so->si, nid);

	return so;
}

void
signed_object_finish(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	cer_finish_ee(&so->ee, so->uri);
	finish_content_info(so, td);
}
