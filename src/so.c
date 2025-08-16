#include "so.h"

#include <libasn1fort/ANY.h>
#include <libasn1fort/CMSAttributeValue.h>
#include <libasn1fort/DigestAlgorithmIdentifier.h>
#include <libasn1fort/SignerInfo.h>

#include "asn1.h"
#include "crl.h"
#include "libcrypto.h"
#include "oid.h"

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
		ext_finish_ski(&si->sid.choice.subjectKeyIdentifier, &ee->SPKI);
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
		si->signature = do_sign(si->signedAttrs,
		    &asn_DEF_SignedAttributes, ee->keys, true);
	}
}

/* Needs the SO _t, and the EE _t. */
static void
finish_signed_data(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	SignedData_t *sd = &so->sd;

	/* Needs the SO _t */
	if (!fields_overridden(so->meta->fields, "content.encapContentInfo.eContent")) {
		pr_debug("- Encoding the eContent");
		sd->encapContentInfo.eContent = pzalloc(sizeof(OCTET_STRING_t));
		der_encode_8str(td, &so->obj, sd->encapContentInfo.eContent);
	}
	/* eContent (DER) ready */

	/* Needs the EE _t */
	// TODO autocomputed even if overridden
	pr_debug("- Encoding the EE");
	der_encode_any(&asn_DEF_Certificate, &so->ee.obj,
	    sd->certificates->list.array[0]);

	/* Needs the EE and eContent (DER) */
	// TODO autocomputed even if overridden
	finish_signer_info(&so->si, &so->ee, so->sd.encapContentInfo.eContent);
}

static void
finish_content_info(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	finish_signed_data(so, td);
	pr_debug("- Encoding the SignedData into the ContentInfo");
	// TODO autocomputed even if overridden
	der_encode_any(&asn_DEF_SignedData, &so->sd, &so->ci.content);
}

static void
init_signer_info(SignerInfo_t *si, int nid, struct field *sif)
{
	CMSAttribute_t *attr;
	OBJECT_IDENTIFIER_t ct;
	Time_t st = { 0 };

	init_INTEGER(&si->version, 3);
	field_add(sif, "version", &ft_int, &si->version, 0);

	/* TODO sid not implemented yet */
//	"sid.issuerAndSerialNumber.", &ft_name, sid.choice.issuerAndSerialNumber.issuer
//	"sid.issuerAndSerialNumber.serialNumber", &ft_int, sid.choice.issuerAndSerialNumber.serialNumber
//	"sid.subjectKeyIdentifier", &ft_8str, sid.choice.subjectKeyIdentifier

	/* ski postponed */

	init_oid(&si->digestAlgorithm.algorithm, NID_sha256);
	/* TODO what happened to params? */
	field_add_algorithm(sif, "digestAlgorithm", &si->digestAlgorithm);

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

	/* TODO signedAttrs field not implemented yet */

	init_oid(&si->signatureAlgorithm.algorithm, NID_rsaEncryption);
	/* TODO what happened to params? */
	field_add_algorithm(sif, "signatureAlgorithm", &si->signatureAlgorithm);

	field_add(sif, "signature", &ft_8str, &si->signature, 0);

	/* TODO unsignedAttrs not implemented yet */
}

struct signed_object *
signed_object_new(struct rpki_object *meta, int nid, struct field **eContent)
{
	struct signed_object *so;
	SignedData_t *sd;
	struct field *sdf;
	DigestAlgorithmIdentifier_t *dai;
	struct field *ecif;
	struct field *cersf, *cerf;
	struct field *sisf, *sif;

	so = pzalloc(sizeof(struct signed_object));
	so->meta = meta;
	sd = &so->sd;

	init_oid(&so->ci.contentType, NID_pkcs7_signed);
	field_add(meta->fields, "contentType", &ft_oid, &so->ci.contentType, 0);
	sdf = field_add(meta->fields, "content", &ft_obj, &so->ci.content, 0);

	init_INTEGER(&sd->version, 3);
	field_add(sdf, "version", &ft_int, &sd->version, 0);

	INIT_ASN1_ARRAY(&sd->digestAlgorithms.list, 1, DigestAlgorithmIdentifier_t);
	dai = (DigestAlgorithmIdentifier_t *)sd->digestAlgorithms.list.array[0];
	init_oid(&dai->algorithm, NID_sha256);
	/* TODO digestAlgorithms field; needs new type */

	init_oid(&sd->encapContentInfo.eContentType, nid);
	/* eContent postponed */
	ecif = field_add(sdf, "encapContentInfo", &ft_obj, &sd->encapContentInfo, 0);
	field_add(ecif, "eContentType", &ft_oid, &sd->encapContentInfo.eContentType, 0);
	*eContent = field_add(ecif, "eContent", &ft_any,
	    &sd->encapContentInfo.eContent, sizeof(OCTET_STRING_t));

	sd->certificates = pzalloc(sizeof(struct CertificateSet));
	INIT_ASN1_ARRAY(&sd->certificates->list, 1, ANY_t);
	cersf = field_add(sdf, "certificates", NULL, NULL, 0);
	cerf = field_add(cersf, "0", &ft_obj, &so->ee, 0);
	so->ee_meta.name = meta->name;
	so->ee_meta.parent = meta->parent;
	so->ee_meta.fields = cerf;
	cer_init(&so->ee, &so->ee_meta, CT_EE);

	/* TODO crls not implemented yet */

	INIT_ASN1_ARRAY(&sd->signerInfos.list, 1, SignerInfo_t);
	sd->signerInfos.list.array[0] = &so->si;
	sisf = field_add(sdf, "signerInfos", NULL, NULL, 0);
	sif = field_add(sisf, "0", &ft_obj, &so->si, 0);
	init_signer_info(&so->si, nid, sif);

	return so;
}

void
signed_object_finish(struct signed_object *so, asn_TYPE_descriptor_t *td)
{
	cer_finish_ee(&so->ee, so->meta->uri);
	finish_content_info(so, td);
}

void
so_print_csv(struct signed_object *so)
{
	char const *type = "unknown";

	switch (so->type) {
	case SO_MFT:	type = "mft";	break;
	case SO_ROA:	type = "roa";	break;
	}

	meta_print_csv(so->meta, type);
	fields_print_csv(so->meta->fields, so->meta->name);
}
