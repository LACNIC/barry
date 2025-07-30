#include "cer.h"

#include <stdbool.h>
#include <stddef.h>

#include "alloc.h"
#include "asn1.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"
#include "print.h"

const struct field_template cer_metadata[] = {
	{
		"tbsCertificate.version",
		&ft_int,
		offsetof(struct rpki_certificate, obj.tbsCertificate.version),
		sizeof(Version_t),
	}, {
		"tbsCertificate.serialNumber",
		&ft_int,
		offsetof(struct rpki_certificate, obj.tbsCertificate.serialNumber),
	}, {
		"tbsCertificate.signature",
		NULL,
		offsetof(struct rpki_certificate, obj.tbsCertificate.signature),
		0,
		algorithm_metadata,
	}, {
		"tbsCertificate.issuer",
		&ft_name,
		offsetof(struct rpki_certificate, obj.tbsCertificate.issuer),
	}, {
		"tbsCertificate.validity.notBefore",
		&ft_time,
		offsetof(struct rpki_certificate, obj.tbsCertificate.validity.notBefore),
	}, {
		"tbsCertificate.validity.notAfter",
		&ft_time,
		offsetof(struct rpki_certificate, obj.tbsCertificate.validity.notAfter),
	}, {
		"tbsCertificate.subject",
		&ft_name,
		offsetof(struct rpki_certificate, obj.tbsCertificate.subject),
	}, {
		"tbsCertificate.subjectPublicKeyInfo.algorithm",
		NULL,
		offsetof(struct rpki_certificate, obj.tbsCertificate.subjectPublicKeyInfo.algorithm),
		0,
		algorithm_metadata,
	}, {
		"tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
		&ft_bitstr,
		offsetof(struct rpki_certificate, obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey),
	},
	/* { "tbsCertificate.issuerUniqueID" }, */
	/* { "tbsCertificate.subjectUniqueID" }, */
	{
		"tbsCertificate.extensions",
		&ft_exts,
		offsetof(struct rpki_certificate, exts),
	}, {
		"signatureAlgorithm",
		NULL,
		offsetof(struct rpki_certificate, obj.signatureAlgorithm),
		0,
		algorithm_metadata,
	}, {
		"signature",
		&ft_bitstr,
		offsetof(struct rpki_certificate, obj.signature),
	},
	{ 0 }
};

static char const *EXT_CTX = "tbsCertificate.extensions";

static void
init_extensions_ta(struct rpki_certificate *ta)
{
	size_t n;

	pr_debug("- Initializing TA extensions");

	INIT_ASN1_ARRAY(&ta->exts.array.list, 7, Extension_t);
	STAILQ_INIT(&ta->exts.list);

	n = 0;
	exts_add_bc(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_ski(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_ku(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_sia(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_cp(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_ip(&ta->exts, n++, ta->fields, EXT_CTX);
	exts_add_asn(&ta->exts, n++, ta->fields, EXT_CTX);
}

static void
init_extensions_ca(struct rpki_certificate *ca)
{
	size_t n;

	pr_debug("- Initializing CA extensions");

	INIT_ASN1_ARRAY(&ca->exts.array.list, 10, Extension_t);
	STAILQ_INIT(&ca->exts.list);

	n = 0;
	exts_add_bc(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_ski(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_aki(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_ku(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_crldp(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_aia(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_sia(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_cp(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_ip(&ca->exts, n++, ca->fields, EXT_CTX);
	exts_add_asn(&ca->exts, n++, ca->fields, EXT_CTX);
}

static void
init_extensions_ee(struct rpki_certificate *ee, struct field *fields,
    char const *ctx)
{
	char key[FIELD_MAXLEN];
	size_t n;

	pr_debug("- Initializing EE extensions");

	INIT_ASN1_ARRAY(&ee->exts.array.list, 9, Extension_t);
	STAILQ_INIT(&ee->exts.list);
	psnprintf(key, FIELD_MAXLEN, "%s.%s", ctx, EXT_CTX);

	n = 0;
	exts_add_ski(&ee->exts, n++, fields, key);
	exts_add_aki(&ee->exts, n++, fields, key);
	exts_add_ku(&ee->exts, n++, fields, key);
	exts_add_crldp(&ee->exts, n++, fields, key);
	exts_add_aia(&ee->exts, n++, fields, key);
	exts_add_sia(&ee->exts, n++, fields, key);
	exts_add_cp(&ee->exts, n++, fields, key);
	exts_add_ip(&ee->exts, n++, fields, key);
	exts_add_asn(&ee->exts, n++, fields, key);
}

struct rpki_certificate *
cer_new(char const *filename, struct rpki_certificate *parent,
    enum cer_type type)
{
	struct rpki_certificate *cer;

	cer = pzalloc(sizeof(struct rpki_certificate));
	cer_init(cer, &cer->fields, filename, parent, type, NULL);

	return cer;
}

void
cer_init(struct rpki_certificate *cer,
    struct field **fields,
    char const *filename,
    struct rpki_certificate *parent, enum cer_type type,
    char const *ctx)
{
	TBSCertificate_t *tbs;

	cer->parent = parent;
	fields_compile(cer_metadata, ctx, cer, fields);
	cer->subject = filename;
	cer->keys = keys_new();
	cer->spki = pubkey2asn1(cer->keys);

	tbs = &cer->obj.tbsCertificate;
	tbs->version = intmax2INTEGER(2);
	init_INTEGER(&tbs->serialNumber, 0);
	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	/* issuer: Postpone (needs parent's subject) */
	init_time_now(&tbs->validity.notBefore);
	init_time_later(&tbs->validity.notAfter);
	init_name(&tbs->subject, filename);
	tbs->subjectPublicKeyInfo = *cer->spki;
	/* tbs->issuerUniqueID: TODO not implemented yet */
	/* tbs->subjectUniqueID: TODO not implemented yet */
	cer->obj.tbsCertificate.extensions = &cer->exts.array;
	init_oid(&cer->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	cer->obj.signatureAlgorithm.parameters = create_null();
	/* cer->signature: Postpone (needs all other fields ready) */

	switch (type) {
	case CT_TA:	init_extensions_ta(cer);		break;
	case CT_CA:	init_extensions_ca(cer);		break;
	case CT_EE:	init_extensions_ee(cer, *fields, ctx);	break;
	}
}

void
cer_generate_paths(struct rpki_certificate *cer, char const *filename)
{
	cer->uri = generate_uri(cer->parent, filename);
	pr_debug("- uri: %s", cer->uri);

	cer->path = generate_path(cer->parent, filename);
	pr_debug("- path: %s", cer->path);

	cer->rpp = rpp_new();
}

void
cer_apply_keyvals(struct rpki_certificate *cer, struct keyvals *kvs)
{
	fields_apply_keyvals(cer->fields, cer, kvs);
}

static bool
is_field_set(struct rpki_certificate *cer, char const *name,
    unsigned int extn, char const *suffix)
{
	return fields_ext_set(cer->fields, EXT_CTX, name, extn, suffix);
}

static void
finish_extensions(struct rpki_certificate *cer, enum cer_type type,
    char const *so_uri)
{
	struct ext_list_node *ext;
	unsigned int extn;

	extn = 0;
	STAILQ_FOREACH(ext, &cer->exts.list, hook) {
		switch (ext->type) {
		case EXT_BC:
		case EXT_CRLN:
			break;

		case EXT_SKI:
			if (!is_field_set(cer, "ski", extn, "extnValue")) {
				switch (type) {
				case CT_TA:
					/* TODO ? */
					finish_ski(&ext->v.ski, &cer->obj.tbsCertificate.subjectPublicKeyInfo);
					break;
				case CT_CA:
				case CT_EE:
					finish_ski(&ext->v.ski, cer->spki);
					break;
				}
			}
			break;

		case EXT_AKI:
			if (!is_field_set(cer, "aki", extn, "extnValue.keyIdentifier")) {
				if (!cer->parent)
					panic("Certificate needs a default AKI, but lacks a parent");
				finish_aki(&ext->v.aki, cer->parent->spki);
			}
			break;

		case EXT_KU:
			if (!is_field_set(cer, "ku", extn, "extnValue"))
				finish_ku(&ext->v.ku, type);
			break;

		case EXT_CRLDP:
			if (!is_field_set(cer, "crldp", extn, "extnValue")) {
				if (!cer->parent)
					panic("Certificate needs a default CRLDP, but lacks a parent");
				finish_crldp(&ext->v.crldp, cer->parent->rpp.crldp);
			}
			break;

		case EXT_AIA:
			if (!is_field_set(cer, "aia", extn, "extnValue"))
				finish_aia(&ext->v.aia, cer->parent->uri);
			break;

		case EXT_SIA:
			if (!is_field_set(cer, "sia", extn, "extnValue")) {
				switch (type) {
				case CT_TA:
				case CT_CA:
					finish_sia_ca(&ext->v.sia,
					    cer->rpp.caRepository,
					    cer->rpp.rpkiManifest,
					    cer->rpp.rpkiNotify);
					break;
				case CT_EE:
					finish_sia_ee(&ext->v.sia, so_uri);
					break;
				}
			}
			break;

		case EXT_CP:
			if (!is_field_set(cer, "cp", extn, "extnValue"))
				finish_cp(&ext->v.cp);
			break;

		case EXT_IP:
			if (!is_field_set(cer, "ip", extn, "extnValue"))
				finish_ip(&ext->v.ip);
			break;

		case EXT_ASN:
			if (!is_field_set(cer, "asn", extn, "extnValue.asnum"))
				finish_asn(&ext->v.asn);
			break;
		}

		extn++;
	}

	extn = 0;
	STAILQ_FOREACH(ext, &cer->exts.list, hook)
		der_encode_8str(ext->td, &ext->v, &cer->exts.array.list.array[extn++]->extnValue);
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
	if (ca->parent == NULL)
		panic("CA '%s' has no parent.", ca->subject);

	if (ca->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ca->obj.tbsCertificate.issuer, ca->parent->subject);
	}
	finish_extensions(ca, CT_CA, NULL);
	update_signature(&ca->obj, ca->parent->keys);
}

void
cer_finish_ee(struct rpki_certificate *ee, char const *so_uri)
{
	if (ee->parent == NULL)
		panic("EE '%s' has no parent.", ee->subject);

	if (ee->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ee->obj.tbsCertificate.issuer, ee->parent->subject);
	}
	finish_extensions(ee, CT_EE, so_uri);
	update_signature(&ee->obj, ee->parent->keys);
}

void
cer_write(struct rpki_certificate *cer)
{
	asn1_write(cer->path, &asn_DEF_Certificate, &cer->obj);
	exec_mkdir(cer->rpp.path);
}

void
cer_print(struct rpki_certificate *cer)
{
	printf("- Type: Certificate\n");
	printf("- URI : %s\n", cer->uri);
	printf("- Path: %s\n", cer->path);
	printf("- RPP:\n");
	printf("\t- caRepository: %s\n", cer->rpp.caRepository);
	printf("\t- rpkiManifest: %s\n", cer->rpp.rpkiManifest);
	printf("\t- crldp       : %s\n", cer->rpp.crldp);
	printf("\t- rpkiNotify  : %s\n", cer->rpp.rpkiNotify);
	printf("\t- Path        : %s\n", cer->rpp.path);

	fields_print(cer->fields);
}
