#include "cer.h"

#include <stdbool.h>
#include <stddef.h>

#include "alloc.h"
#include "asn1.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"
#include "print.h"

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
	TBSCertificate_t *tbs;
	struct field *tbsf;
	struct field *extf;

	cer->meta = meta;
	cer->subject = meta->name; // XXX remove subject?
	cer->keys = keys_new();
	cer->spki = pubkey2asn1(cer->keys);

	tbs = &cer->obj.tbsCertificate;
	tbsf = field_add_static(meta->fields, "tbsCertificate");

	tbs->version = intmax2INTEGER(2);
	field_add(tbsf, "version", &ft_int, &tbs->version, sizeof(Version_t));

	init_INTEGER(&tbs->serialNumber, 0);
	field_add(tbsf, "serialNumber", &ft_int, &tbs->serialNumber, 0);

	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	field_add_algorithm(tbsf, "signature", &tbs->signature);

	/* issuer: Postpone (needs parent's subject) */
	field_add(tbsf, "issuer", &ft_name, &tbs->issuer, 0);

	init_time_now(&tbs->validity.notBefore);
	field_add(tbsf, "validity.notBefore", &ft_time, &tbs->validity.notBefore, 0);

	init_time_later(&tbs->validity.notAfter);
	field_add(tbsf, "validity.notAfter", &ft_time, &tbs->validity.notAfter, 0);

	init_name(&tbs->subject, meta->name);
	field_add(tbsf, "subject", &ft_name, &tbs->subject, 0);

	tbs->subjectPublicKeyInfo = *cer->spki;
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
	field_add(meta->fields, "signature", &ft_bitstr, &tbs->signature, 0);
}

static void
finish_extensions(struct rpki_certificate *cer, enum cer_type type,
    char const *so_uri)
{
	struct field *fields;
	struct ext_list_node *ext;
	unsigned int extn;

	fields = cer->meta->fields;
	extn = 0;

	STAILQ_FOREACH(ext, &cer->exts, hook) {

		switch (ext->type) {
		case EXT_BC:
			pr_trace("Finishing BC");
			break;

		case EXT_SKI:
			pr_trace("Finishing SKI");
			if (!ext_field_set(fields, "ski", extn, "extnValue")) {
				switch (type) {
				case CT_TA:
					/* TODO ? */
					ext_finish_ski(&ext->v.ski, &cer->obj.tbsCertificate.subjectPublicKeyInfo);
					break;
				case CT_CA:
				case CT_EE:
					ext_finish_ski(&ext->v.ski, cer->spki);
					break;
				}
			}
			break;

		case EXT_AKI:
			pr_trace("Finishing AKI");
			if (!ext_field_set(fields, "aki", extn, "extnValue.keyIdentifier")) {
				if (!cer->meta->parent)
					panic("Certificate needs a default AKI, but lacks a parent");
				ext_finish_aki(&ext->v.aki, cer->meta->parent->spki);
			}
			break;

		case EXT_KU:
			pr_trace("Finishing KU");
			if (!ext_field_set(fields, "ku", extn, "extnValue"))
				ext_finish_ku(&ext->v.ku, type);
			break;

		case EXT_CRLDP:
			pr_trace("Finishing CRLDP");
			if (!ext_field_set(fields, "crldp", extn, "extnValue")) {
				if (!cer->meta->parent)
					panic("Certificate needs a default CRLDP, but lacks a parent");
				ext_finish_crldp(&ext->v.crldp,
				    cer->meta->parent->rpp.crldp);
			}
			break;

		case EXT_AIA:
			pr_trace("Finishing AIA");
			if (!ext_field_set(fields, "aia", extn, "extnValue"))
				ext_finish_aia(&ext->v.aia,
				    cer->meta->parent->meta->uri);
			break;

		case EXT_SIA:
			pr_trace("Finishing SIA");
			if (!ext_field_set(fields, "sia", extn, "extnValue")) {
				switch (type) {
				case CT_TA:
				case CT_CA:
					ext_finish_sia_ca(&ext->v.sia,
					    cer->rpp.caRepository,
					    cer->rpp.rpkiManifest,
					    cer->rpp.rpkiNotify);
					break;
				case CT_EE:
					ext_finish_sia_ee(&ext->v.sia, so_uri);
					break;
				}
			}
			break;

		case EXT_CP:
			pr_trace("Finishing CP");
			if (!ext_field_set(fields, "cp", extn, "extnValue"))
				ext_finish_cp(&ext->v.cp);
			break;

		case EXT_IP:
			pr_trace("Finishing IP");
			if (!ext_field_set(fields, "ip", extn, "extnValue"))
				ext_finish_ip(&ext->v.ip);
			break;

		case EXT_ASN:
			pr_trace("Finishing ASN");
			if (!ext_field_set(fields, "asn", extn, "extnValue.asnum"))
				ext_finish_asn(&ext->v.asn);
			break;

		case EXT_CRLN:
			pr_trace("Finishing CRLN");
			break;
		}

		extn++;
	}

	ext_compile(&cer->exts, &cer->obj.tbsCertificate.extensions);
}

static void
update_signature(Certificate_t *cer, EVP_PKEY *privkey)
{
	unsigned char tbscer[4096];
	asn_enc_rval_t rval;
	SignatureValue_t signature;

	// TODO autocomputed even if overridden

	pr_debug("- Signing");

	rval = der_encode_to_buffer(&asn_DEF_TBSCertificate,
	    &cer->tbsCertificate, tbscer, sizeof(tbscer));
	if (rval.encoded < 0)
		panic("TBSCertificate rval.encoded: %zd", rval.encoded);

	signature = do_sign(privkey, tbscer, rval.encoded);
	cer->signature.buf = signature.buf;
	cer->signature.size = signature.size;
}

void
cer_generate_paths(struct rpki_certificate *cer)
{
	cer->rpp = rpp_new();
}

void
cer_finish_ta(struct rpki_certificate *ta)
{
	if (ta->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		ta->obj.tbsCertificate.issuer = ta->obj.tbsCertificate.subject;
	}
	finish_extensions(ta, CT_TA, NULL);
	update_signature(&ta->obj, ta->keys);
}

void
cer_finish_ca(struct rpki_certificate *ca)
{
	if (ca->meta->parent == NULL)
		panic("CA '%s' has no parent.", ca->subject);
	if (ca->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ca->obj.tbsCertificate.issuer, ca->meta->parent->subject);
	}
	finish_extensions(ca, CT_CA, NULL);
	update_signature(&ca->obj, ca->meta->parent->keys);
}

void
cer_finish_ee(struct rpki_certificate *ee, char const *so_uri)
{
	if (ee->meta->parent == NULL)
		panic("EE '%s' has no parent.", ee->subject);

	if (ee->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ee->obj.tbsCertificate.issuer, ee->meta->parent->subject);
	}
	finish_extensions(ee, CT_EE, so_uri);
	update_signature(&ee->obj, ee->meta->parent->keys);
}

void
cer_write(struct rpki_certificate *cer)
{
	asn1_write(cer->meta->path, &asn_DEF_Certificate, &cer->obj);
	exec_mkdir(cer->rpp.path);
}

void
cer_print(struct rpki_certificate *cer)
{
	printf("- Type: Certificate\n");
	printf("- RPP:\n");
	printf("\t- caRepository: %s\n", cer->rpp.caRepository);
	printf("\t- rpkiManifest: %s\n", cer->rpp.rpkiManifest);
	printf("\t- crldp       : %s\n", cer->rpp.crldp);
	printf("\t- rpkiNotify  : %s\n", cer->rpp.rpkiNotify);
	printf("\t- Path        : %s\n", cer->rpp.path);
}
