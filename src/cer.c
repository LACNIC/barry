#include "cer.h"

#include <stdbool.h>
#include <stddef.h>

#include "alloc.h"
#include "asn1.h"
#include "csv.h"
#include "field.h"
#include "file.h"
#include "libcrypto.h"
#include "oid.h"
#include "print.h"
#include "rpki_object.h"

static void
init_extensions_ta(struct rpki_certificate *ta, struct field *extf)
{
	size_t n;

	pr_debug("- Initializing TA extensions");

	STAILQ_INIT(&ta->exts);

	n = 0;
	exts_add_bc(&ta->exts, n++, extf);
	exts_add_ski(&ta->exts, n++, extf);
	exts_add_ku(&ta->exts, n++, extf);
	exts_add_sia(&ta->exts, n++, extf);
	exts_add_cp(&ta->exts, n++, extf);
	exts_add_ip(&ta->exts, n++, extf);
	exts_add_asn(&ta->exts, n++, extf);
}

static void
init_extensions_ca(struct rpki_certificate *ca, struct field *extf)
{
	size_t n;

	pr_debug("- Initializing CA extensions");

	STAILQ_INIT(&ca->exts);

	n = 0;
	exts_add_bc(&ca->exts, n++, extf);
	exts_add_ski(&ca->exts, n++, extf);
	exts_add_aki(&ca->exts, n++, extf);
	exts_add_ku(&ca->exts, n++, extf);
	exts_add_crldp(&ca->exts, n++, extf);
	exts_add_aia(&ca->exts, n++, extf);
	exts_add_sia(&ca->exts, n++, extf);
	exts_add_cp(&ca->exts, n++, extf);
	exts_add_ip(&ca->exts, n++, extf);
	exts_add_asn(&ca->exts, n++, extf);
}

static void
init_extensions_ee(struct rpki_certificate *ee, struct field *extf)
{
	size_t n;

	pr_debug("- Initializing EE extensions");

	STAILQ_INIT(&ee->exts);

	n = 0;
	exts_add_ski(&ee->exts, n++, extf);
	exts_add_aki(&ee->exts, n++, extf);
	exts_add_ku(&ee->exts, n++, extf);
	exts_add_crldp(&ee->exts, n++, extf);
	exts_add_aia(&ee->exts, n++, extf);
	exts_add_sia(&ee->exts, n++, extf);
	exts_add_cp(&ee->exts, n++, extf);
	exts_add_ip(&ee->exts, n++, extf);
	exts_add_asn(&ee->exts, n++, extf);
}

struct rpki_certificate *
cer_new(struct rpki_object *meta, enum cer_type type)
{
	struct rpki_certificate *cer;

	cer = pzalloc(sizeof(struct rpki_certificate));
	cer_init(cer, meta, type);

	return cer;
}

void
cer_init(struct rpki_certificate *cer, struct rpki_object *meta,
    enum cer_type type)
{
	struct field *rppf;
	TBSCertificate_t *tbs;
	struct field *tbsf;
	struct field *valf;
	struct field *extf;

	cer->meta = meta;
	rppf = field_add(meta->fields, "rpp", &ft_obj, &cer->rpp, 0);
	field_add(rppf, "rpkiNotify", &ft_notif, cer, 0);
	cer->keys = keys_new();

	tbs = &cer->obj.tbsCertificate;
	tbsf = field_add(meta->fields, "tbsCertificate", &ft_obj, tbs, 0);

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
	extf = field_add(tbsf, "extensions", &ft_exts, &cer->exts, 0);
	switch (type) {
	case CT_TA:	init_extensions_ta(cer, extf);		break;
	case CT_CA:	init_extensions_ca(cer, extf);		break;
	case CT_EE:	init_extensions_ee(cer, extf);		break;
	}

	init_oid(&cer->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	cer->obj.signatureAlgorithm.parameters = create_null();
	field_add_algorithm(meta->fields, "signatureAlgorithm", &cer->obj.signatureAlgorithm);

	/* cer->signature: Postpone (needs all other fields ready) */
	field_add(meta->fields, "signature", &ft_bitstr, &cer->obj.signature, 0);
}

static void
finish_aki(AuthorityKeyIdentifier_t *aki, struct rpki_certificate *cer)
{
	if (!cer->meta->parent)
		panic("Certificate needs a default AKI, but lacks a parent");
	ext_finish_aki(aki, &cer->meta->parent->SPKI);
}

static void
finish_crldp(CRLDistributionPoints_t *crldp, struct rpki_certificate *cer)
{
	if (!cer->meta->parent)
		panic("Certificate needs a default CRLDP, but lacks a parent");
	ext_finish_crldp(crldp, cer->meta->parent->rpp.crldp);
}

static void
finish_aia(AuthorityInfoAccessSyntax_t *aia, struct rpki_certificate *cer)
{
	if (!cer->meta->parent)
		panic("Certificate needs a default AIA, but lacks a parent");
	ext_finish_aia(aia, cer->meta->parent->meta->uri);
}

static void
finish_sia(SubjectInfoAccessSyntax_t *sia, struct rpki_certificate *cer,
    enum cer_type type, char const *so_uri)
{
	switch (type) {
	case CT_TA:
	case CT_CA:
		ext_finish_sia_ca(sia,
		    cer->rpp.caRepository,
		    cer->rpp.rpkiManifest,
		    cer->rpp.rpkiNotify);
		break;
	case CT_EE:
		ext_finish_sia_ee(sia, so_uri);
		break;
	}
}

static void
finish_extensions(struct rpki_certificate *cer, enum cer_type type,
    char const *so_uri)
{
	struct ext_list_node *ext;
	unsigned int extn;
	struct field *fld;

	pr_debug("- Autofilling extensions");

	extn = 0;
	fld = fields_find(cer->meta->fields, "tbsCertificate.extensions");
	if (!fld)
		panic("Certificate lacks a 'tbsCertificate.extensions' field.");

	STAILQ_FOREACH(ext, &cer->exts, hook) {
		switch (ext->type) {
		case EXT_BC:
		case EXT_CRLN:
			break;

		case EXT_SKI:
			if (!EXT_FIELD_SET(fld, "ski", extn, ))
				ext_finish_ski(&ext->v.ski, &cer->SPKI);
			break;

		case EXT_AKI:
			if (!EXT_FIELD_SET(fld, "aki", extn, ".keyIdentifier"))
				finish_aki(&ext->v.aki, cer);
			break;

		case EXT_KU:
			if (!EXT_FIELD_SET(fld, "ku", extn, ))
				ext_finish_ku(&ext->v.ku, type);
			break;

		case EXT_CRLDP:
			if (!EXT_FIELD_SET(fld, "crldp", extn, ))
				finish_crldp(&ext->v.crldp, cer);
			break;

		case EXT_AIA:
			if (!EXT_FIELD_SET(fld, "aia", extn, ))
				finish_aia(&ext->v.aia, cer);
			break;

		case EXT_SIA:
			if (!EXT_FIELD_SET(fld, "sia", extn, ))
				finish_sia(&ext->v.sia, cer, type, so_uri);
			break;

		case EXT_CP:
			if (!EXT_FIELD_SET(fld, "cp", extn, ))
				ext_finish_cp(&ext->v.cp);
			break;

		case EXT_IP:
			if (!EXT_FIELD_SET(fld, "ip", extn, ))
				ext_finish_ip(&ext->v.ip);
			break;

		case EXT_ASN:
			if (!EXT_FIELD_SET(fld, "asn", extn, ".asnum"))
				ext_finish_asn(&ext->v.asn);
			break;
		}

		extn++;
	}

	ext_compile(&cer->exts, &cer->obj.tbsCertificate.extensions);
}

static void
update_signature(struct rpki_certificate *cer, EVP_PKEY *keys)
{
	SignatureValue_t signature;

	if (fields_overridden(cer->meta->fields, "signature")) {
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
cer_generate_paths(struct rpki_certificate *cer)
{
	cer->rpp = rpp_new(cer);
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

static void
finish_rpp(struct rpki_certificate *cer, char *obj_name)
{
	struct rrdp_notification *notif;

	if (fields_overridden(cer->meta->fields, "rpp.rpkiNotify"))
		return;

	pr_debug("- Autofilling rpkiNotify");

	cer->rpp.rpkiNotify = cer->meta->parent->rpp.rpkiNotify;
	if (cer->rpp.rpkiNotify == NULL) {
		pr_trace("There's no rpkiNotify to inherit.");
		return;
	}

	notif = notif_getsert(cer->meta->tree, cer->rpp.rpkiNotify);
	notif_add_file(notif, obj_name);
}

void
cer_finish_ca(struct rpki_certificate *ca)
{
	if (ca->meta->parent == NULL)
		panic("CA '%s' has no parent.", ca->meta->name);
	if (ca->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ca->obj.tbsCertificate.issuer,
		    ca->meta->parent->meta->name);
	}
	finish_rpp(ca, ca->meta->name);
	finish_extensions(ca, CT_CA, NULL);
	update_signature(ca, ca->meta->parent->keys);
}

void
cer_finish_ee(struct rpki_certificate *ee, struct rpki_object *so)
{
	if (ee->meta->parent == NULL)
		panic("EE '%s' has no parent.", ee->meta->name);

	if (ee->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ee->obj.tbsCertificate.issuer,
		    ee->meta->parent->meta->name);
	}
	finish_rpp(ee, so->name);
	finish_extensions(ee, CT_EE, so->uri);
	update_signature(ee, ee->meta->parent->keys);
}

void
cer_write(struct rpki_certificate *cer)
{
	asn1_write(cer->meta->path, &asn_DEF_Certificate, &cer->obj);
	exec_mkdir(cer->rpp.path);
}

void
cer_print_md(struct rpki_certificate *cer)
{
	printf("- Type: Certificate\n");
	printf("- RPP:\n");
	printf("\t- caRepository: %s\n", cer->rpp.caRepository);
	printf("\t- rpkiManifest: %s\n", cer->rpp.rpkiManifest);
	printf("\t- crldp       : %s\n", cer->rpp.crldp);
	printf("\t- rpkiNotify  : %s\n", cer->rpp.rpkiNotify);
	printf("\t- Path        : %s\n", cer->rpp.path);
}

void
cer_print_csv(struct rpki_certificate *cer)
{
	meta_print_csv(cer->meta);

	csv_print3(cer->meta, "caRepository", cer->rpp.caRepository);
	csv_print3(cer->meta, "rpkiManifest", cer->rpp.rpkiManifest);
	csv_print3(cer->meta, "crldp", cer->rpp.crldp);
	csv_print3(cer->meta, "rpkiNotify", cer->rpp.rpkiNotify);
	csv_print3(cer->meta, "rpp", cer->rpp.path);

	fields_print_csv(cer->meta->fields, cer->meta->name);
}
