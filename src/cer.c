#include "cer.h"

#include <libasn1fort/TBSCertificate.h>
#include <libasn1fort/Version.h>
#include <openssl/obj_mac.h>

#include "asn1.h"
#include "file.h"
#include "keys.h"
#include "signature.h"

static void
init_extensions_ta(struct rpki_certificate *ta, struct field *extf)
{
	pr_debug("- Initializing TA extensions");

	STAILQ_INIT(&ta->exts);

	exts_add_bc(&ta->exts, "bc", extf);
	exts_add_ski(&ta->exts, "ski", extf);
	exts_add_ku(&ta->exts, "ku", extf);
	exts_add_sia(&ta->exts, "sia", extf, sia_ca_defaults);
	exts_add_cp(&ta->exts, "cp", extf);
	exts_add_ip(&ta->exts, "ip", extf);
	exts_add_asn(&ta->exts, "asn", extf);
}

static void
init_extensions_ca(struct rpki_certificate *ca, struct field *extsf)
{
	pr_debug("- Initializing CA extensions");

	STAILQ_INIT(&ca->exts);

	exts_add_bc(&ca->exts, "bc", extsf);
	exts_add_ski(&ca->exts, "ski", extsf);
	exts_add_aki(&ca->exts, "aki", extsf);
	exts_add_ku(&ca->exts, "ku", extsf);
	exts_add_crldp(&ca->exts, "crldp", extsf);
	exts_add_aia(&ca->exts, "aia", extsf);
	exts_add_sia(&ca->exts, "sia", extsf, sia_ca_defaults);
	exts_add_cp(&ca->exts, "cp", extsf);
	exts_add_ip(&ca->exts, "ip", extsf);
	exts_add_asn(&ca->exts, "asn", extsf);
}

static void
init_extensions_ee(struct rpki_certificate *ee, struct field *extf)
{
	pr_debug("- Initializing EE extensions");

	STAILQ_INIT(&ee->exts);

	exts_add_ski(&ee->exts, "ski", extf);
	exts_add_aki(&ee->exts, "aki", extf);
	exts_add_ku(&ee->exts, "ku", extf);
	exts_add_crldp(&ee->exts, "crldp", extf);
	exts_add_aia(&ee->exts, "aia", extf);
	exts_add_sia(&ee->exts, "sia", extf, sia_ee_defaults);
	exts_add_cp(&ee->exts, "cp", extf);
	exts_add_ip(&ee->exts, "ip", extf);
	/*
	 * This `if` is an rpki-client quirk.
	 * They ban ASN extensions in ROAs. AFAIK, this is not RFC'd, but makes
	 * sense... although it doesn't seem consistent with their treatment of
	 * other SOs.
	 */
	if (ee->meta->node->type != FT_ROA)
		exts_add_asn(&ee->exts, "asn", extf);
}

struct rpki_certificate *
cer_new(struct rpki_tree_node *node, enum cer_type type)
{
	struct rpki_certificate *cer;

	cer = pzalloc(sizeof(struct rpki_certificate));

	cer->rppf = field_add(node->fields, "rpp", &ft_obj, &cer->rpp, 0);
	field_add(cer->rppf, "uri", &ft_cstr, &cer->rpp.uri, 0);
	field_add(cer->rppf, "path", &ft_cstr, &cer->rpp.path, 0);
	field_add(cer->rppf, "notification", &ft_cstr, &cer->rpp.notification, 0);
	cer->objf = field_add(node->fields, "obj", &ft_obj, &cer->obj, 0);

	cer_init(cer, &node->meta, type);

	return cer;
}

static void
pubkey2asn1(EVP_PKEY *pubkey, SubjectPublicKeyInfo_t *asn1)
{
	unsigned char *der;
	size_t derlen;

	pubkey2der(pubkey, &der, &derlen);
	ber2asn1(der, derlen, &asn_DEF_SubjectPublicKeyInfo, asn1);
}

void
cer_init(struct rpki_certificate *cer, struct rpki_object *meta,
    enum cer_type type)
{
	TBSCertificate_t *tbs;
	struct field *tbsf;
	struct field *valf;
	struct field *extsf;

	cer->meta = meta;
	cer->keys = keys_new();

	tbs = &cer->obj.tbsCertificate;
	tbsf = field_add(cer->objf, "tbsCertificate", &ft_obj, tbs, 0);

	tbs->version = intmax2INTEGER(2);
	field_add(tbsf, "version", &ft_int, &tbs->version, sizeof(Version_t));

	init_INTEGER(&tbs->serialNumber, 0);
	field_add(tbsf, "serialNumber", &ft_int, &tbs->serialNumber, 0);

	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	field_add_algorithm(tbsf, "signature", &tbs->signature);

	/* issuer: Postpone (needs parent's subject) */
	field_add_name(tbsf, "issuer", &tbs->issuer);

	init_time_now(&tbs->validity.notBefore);
	init_time_later(&tbs->validity.notAfter);
	valf = field_add(tbsf, "validity", &ft_obj, &tbs->validity, 0);
	field_add(valf, "notBefore", &ft_time, &tbs->validity.notBefore, 0);
	field_add(valf, "notAfter", &ft_time, &tbs->validity.notAfter, 0);

	init_name(&tbs->subject, meta->name);
	field_add_name(tbsf, "subject", &tbs->subject);

	pubkey2asn1(cer->keys, &tbs->subjectPublicKeyInfo);
	field_add_spki(tbsf, "subjectPublicKeyInfo", &tbs->subjectPublicKeyInfo);

	/* tbs->issuerUniqueID: TODO not implemented yet */
	/* tbs->subjectUniqueID: TODO not implemented yet */

	tbs->extensions = NULL;
	extsf = field_add(tbsf, "extensions", &ft_exts, &cer->exts, 0);
	switch (type) {
	case CT_TA:	init_extensions_ta(cer, extsf);		break;
	case CT_CA:	init_extensions_ca(cer, extsf);		break;
	case CT_EE:	init_extensions_ee(cer, extsf);		break;
	}

	init_oid(&cer->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	cer->obj.signatureAlgorithm.parameters = create_null();
	field_add_algorithm(cer->objf, "signatureAlgorithm", &cer->obj.signatureAlgorithm);

	/* cer->signature: Postpone (needs all other fields ready) */
	field_add(cer->objf, "signature", &ft_bitstr, &cer->obj.signature, 0);
}

static void
finish_aki(AuthorityKeyIdentifier_t *aki, struct rpki_certificate *cer)
{
	struct rpki_certificate *parent;

	parent = cer_parent(cer);
	if (!parent)
		panic("Certificate needs a default AKI, but lacks a parent");
	ext_finish_aki(aki, &parent->SPKI);
}

static void
finish_crldp(CRLDistributionPoints_t *crldp, struct rpki_certificate *cer)
{
	if (!cer_parent(cer))
		panic("Certificate needs a default CRLDP, but lacks a parent");
	ext_finish_crldp(crldp, cer_crldp(cer));
}

static void
finish_aia(AuthorityInfoAccessSyntax_t *aia, struct field *extnValuef,
    struct rpki_certificate *cer)
{
	struct rpki_certificate *parent;

	parent = cer_parent(cer);
	if (!parent)
		panic("Certificate needs a default AIA, but lacks a parent");
	ext_finish_aia(aia, extnValuef, parent->meta->uri);
}

static void
finish_extensions(struct rpki_certificate *cer, enum cer_type type,
    struct rpki_object *so)
{
	struct ext_list_node *ext;
	struct field *extsf;
	struct field *extnValuef;

	pr_debug("- Autofilling extensions");

	extsf = fields_find(cer->objf, "tbsCertificate.extensions");
	if (!extsf)
		panic("Certificate lacks a 'tbsCertificate.extensions' field.");

	STAILQ_FOREACH(ext, &cer->exts, hook) {
		extnValuef = fields_find(fields_find(extsf, ext->name), "extnValue");

		switch (ext->type) {
		case EXT_BC:
		case EXT_CRLN:
			break;

		case EXT_SKI:
			if (!fields_overridden(extnValuef, NULL))
				ext_finish_ski(&ext->v.ski, &cer->SPKI);
			break;

		case EXT_AKI:
			if (!fields_overridden(extnValuef, "keyIdentifier"))
				finish_aki(&ext->v.aki, cer);
			break;

		case EXT_KU:
			if (!fields_overridden(extnValuef, NULL))
				ext_finish_ku(&ext->v.ku, type);
			break;

		case EXT_CRLDP:
			if (!fields_overridden(extnValuef, NULL))
				finish_crldp(&ext->v.crldp, cer);
			break;

		case EXT_AIA:
			finish_aia(&ext->v.aia, extnValuef, cer);
			break;

		case EXT_SIA:
			ext_finish_sia(&ext->v.sia, extnValuef, cer,
			    so ? so->uri : NULL);
			break;

		case EXT_CP:
			if (!fields_overridden(extnValuef, NULL))
				ext_finish_cp(&ext->v.cp);
			break;

		case EXT_IP:
			if (!fields_overridden(extnValuef, NULL))
				ext_finish_ip(&ext->v.ip, so);
			break;

		case EXT_ASN:
			if (!fields_overridden(extnValuef, "asnum"))
				ext_finish_asn(&ext->v.asn, so);
			break;
		}
	}

	ext_compile(&cer->exts, &cer->obj.tbsCertificate.extensions);
}

static void
update_signature(struct rpki_certificate *cer, EVP_PKEY *keys)
{
	SignatureValue_t signature;

	if (fields_overridden(cer->objf, "signature")) {
		pr_debug("- Skipping signature");
		return;
	}

	pr_debug("- Signing");
	signature = do_sign(&cer->obj.tbsCertificate, &asn_DEF_TBSCertificate,
	    keys, false);
	cer->obj.signature.buf = signature.buf;
	cer->obj.signature.size = signature.size;
}

void
cer_finish_rpp(struct rpki_certificate *cer)
{
	extern char const *rsync_uri;
	extern char const *rrdp_uri;

	char *extless;
	struct rpki_certificate *parent;

	extless = remove_extension(cer->meta->name);

	if (!fields_overridden(cer->rppf, "uri")) {
		cer->rpp.uri = join_paths(rsync_uri, extless);
		pr_debug("- rpp.uri: %s", cer->rpp.uri);
	}

	if (!fields_overridden(cer->rppf, "path")) {
		cer->rpp.path = pstrdup(extless);
		pr_debug("- rpp.path: %s", cer->rpp.path);
	}

	if (!fields_overridden(cer->rppf, "notification")) {
		parent = cer_parent(cer);
		cer->rpp.notification = (parent == NULL)
		    ? join_paths(rrdp_uri, "notification.xml")
		    : parent->rpp.notification;
		pr_debug("- rpp.notification: %s", cer->rpp.notification);
	}

	free(extless);
}

void
cer_finish_ta(struct rpki_certificate *ta)
{
	if (ta->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		ta->obj.tbsCertificate.issuer = ta->obj.tbsCertificate.subject;
	}
	finish_extensions(ta, CT_TA, NULL);
	update_signature(ta, ta->keys);
}

void
cer_finish_ca(struct rpki_certificate *ca)
{
	struct rpki_certificate *parent;

	parent = cer_parent(ca);
	if (parent == NULL)
		panic("CA '%s' has no parent.", ca->meta->name);

	if (ca->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ca->obj.tbsCertificate.issuer, parent->meta->name);
	}
	finish_extensions(ca, CT_CA, NULL);
	update_signature(ca, parent->keys);
}

void
cer_finish_ee(struct rpki_certificate *ee, struct rpki_object *so)
{
	struct rpki_certificate *parent;

	parent = cer_parent(ee);
	if (parent == NULL)
		panic("EE '%s' has no parent.", ee->meta->name);

	if (ee->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ee->obj.tbsCertificate.issuer, parent->meta->name);
	}
	finish_extensions(ee, CT_EE, so);
	update_signature(ee, parent->keys);
}

void
cer_write(struct rpki_certificate *cer)
{
	asn1_write(cer->meta->path, &asn_DEF_Certificate, &cer->obj);
}

struct rpki_certificate *
cer_parent(struct rpki_certificate *cer)
{
	return meta_parent(cer->meta);
}

char const *
cer_rpkiManifest(struct rpki_certificate *cer)
{
	struct rpki_tree_node *child, *tmp;

	HASH_ITER(phook, cer->meta->node->children, child, tmp)
		if (child->type == FT_MFT)
			return child->meta.uri;

	return NULL;
}

char const *
cer_crldp(struct rpki_certificate *cer)
{
	struct rpki_tree_node *parent, *child, *tmp;

	parent = cer->meta->node->parent;
	if (!parent)
		return NULL;

	HASH_ITER(phook, parent->children, child, tmp)
		if (child->type == FT_CRL)
			return child->meta.uri;

	return NULL;
}
