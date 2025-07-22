#include "cer.h"

#include <stdbool.h>
#include <stddef.h>

#include "alloc.h"
#include "asn1.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"
#include "print.h"

const struct field cer_metadata[] = {
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
		"tbsCertificate.extensions[ip]",
		&ft_ip_cer,
		offsetof(struct rpki_certificate, ip),
	}, {
		"tbsCertificate.extensions[asn]",
		&ft_asn_cer,
		offsetof(struct rpki_certificate, asn),
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

static struct field *cer_fields;

static void
init_extensions_ta(struct rpki_certificate *ta)
{
	struct Extensions *exts;
	BasicConstraints_t bc = { 0 };
	SubjectKeyIdentifier_t ski = { 0 };
	KeyUsage_t eku = { 0 };
	SubjectInfoAccessSyntax_t sia = { 0 };
	CertificatePolicies_t cp = { 0 };

	pr_debug("- Initializing TA extensions");

	exts = pzalloc(sizeof(struct Extensions));
	ta->obj.tbsCertificate.extensions = exts;
	INIT_ASN1_ARRAY(&exts->list, 7, Extension_t);

	/* Basic Constraints */
	init_bc(&bc);
	init_ext(exts->list.array[0], &asn_DEF_BasicConstraints, NID_basic_constraints, true, &bc);

	/* Subject Key Identifier */
	init_ski(&ski, &ta->obj.tbsCertificate.subjectPublicKeyInfo);
	init_ext(exts->list.array[1], &asn_DEF_SubjectKeyIdentifier, NID_subject_key_identifier, false, &ski);

	/* Key Usage */
	init_ku_ca(&eku);
	init_ext(exts->list.array[2], &asn_DEF_KeyUsage, NID_key_usage, true, &eku);

	/* SIA */
	init_sia_ca(&sia, ta->rpp.caRepository, ta->rpp.rpkiManifest, ta->rpp.rpkiNotify);
	init_ext(exts->list.array[3], &asn_DEF_SubjectInfoAccessSyntax, NID_sinfo_access, false, &sia);

	/* Certificate Policies */
	init_cp(&cp);
	init_ext(exts->list.array[4], &asn_DEF_CertificatePolicies, NID_certificate_policies, true, &cp);

	/* IP Address Blocks */
	init_ext(exts->list.array[5], &asn_DEF_IPAddrBlocks, NID_ip_v2, true, &ta->ip);

	/* ASNs */
	init_ext(exts->list.array[6], &asn_DEF_ASIdentifiers, NID_asn_v2, true, &ta->asn);
}

static void
init_extensions_ca(struct rpki_certificate *ca)
{
	Extensions_t *exts;
	BasicConstraints_t bc = { 0 };
	AuthorityKeyIdentifier_t aki = { 0 };
	KeyUsage_t eku = { 0 };
	CRLDistributionPoints_t crldp = { 0 };
	AuthorityInfoAccessSyntax_t aia = { 0 };
	SubjectInfoAccessSyntax_t sia = { 0 };
	CertificatePolicies_t cp = { 0 };

	if (ca->parent == NULL)
		panic("CA '%s' has no parent.", ca->subject);

	pr_debug("- Initializing CA extensions");

	exts = pzalloc(sizeof(struct Extensions));
	ca->obj.tbsCertificate.extensions = exts;
	INIT_ASN1_ARRAY(&exts->list, 10, Extension_t);

	/* Basic Constraints */
	init_bc(&bc);
	init_ext(exts->list.array[0], &asn_DEF_BasicConstraints, NID_basic_constraints, true, &bc);

	/* Subject Key Identifier */
	init_ski(&ca->ski, ca->spki);
	init_ext(exts->list.array[1], &asn_DEF_SubjectKeyIdentifier, NID_subject_key_identifier, false, &ca->ski);

	/* Authority Key Identifier */
	init_aki(&aki, ca->parent->spki);
	init_ext(exts->list.array[2], &asn_DEF_AuthorityKeyIdentifier, NID_authority_key_identifier, false, &aki);

	/* Extended Key Usage */
	init_ku_ca(&eku);
	init_ext(exts->list.array[3], &asn_DEF_KeyUsage, NID_key_usage, true, &eku);

	/* CRL Distribution Points */
	init_crldp(&crldp, ca->parent->rpp.crldp);
	init_ext(exts->list.array[4], &asn_DEF_CRLDistributionPoints, NID_crl_distribution_points, false, &crldp);

	/* AIA */
	init_aia(&aia, ca->parent->uri);
	init_ext(exts->list.array[5], &asn_DEF_AuthorityInfoAccessSyntax, NID_info_access, false, &aia);

	/* SIA */
	init_sia_ca(&sia, ca->rpp.caRepository, ca->rpp.rpkiManifest, ca->rpp.rpkiNotify);
	init_ext(exts->list.array[6], &asn_DEF_SubjectInfoAccessSyntax, NID_sinfo_access, false, &sia);

	/* Certificate Policies */
	init_cp(&cp);
	init_ext(exts->list.array[7], &asn_DEF_CertificatePolicies, NID_certificate_policies, true, &cp);

	/* IP Address Blocks */
	init_ext(exts->list.array[8], &asn_DEF_IPAddrBlocks, NID_ip_v2, true, &ca->ip);

	/* ASNs */
	init_ext(exts->list.array[9], &asn_DEF_ASIdentifiers, NID_asn_v2, true, &ca->asn);
}

static void
init_extensions_ee(struct rpki_certificate *ee, char const *so_uri)
{
	Extensions_t *exts;
	AuthorityKeyIdentifier_t aki = { 0 };
	KeyUsage_t eku = { 0 };
	CRLDistributionPoints_t crldp = { 0 };
	AuthorityInfoAccessSyntax_t aia = { 0 };
	SubjectInfoAccessSyntax_t sia = { 0 };
	CertificatePolicies_t cp = { 0 };

	pr_debug("- Initializing EE extensions");

	exts = pzalloc(sizeof(struct Extensions));
	ee->obj.tbsCertificate.extensions = exts;
	INIT_ASN1_ARRAY(&exts->list, 9, Extension_t);

	/* Subject Key Identifier */
	init_ski(&ee->ski, ee->spki);
	init_ext(exts->list.array[0], &asn_DEF_SubjectKeyIdentifier, NID_subject_key_identifier, false, &ee->ski);

	/* Authority Key Identifier */
	init_aki(&aki, ee->parent->spki);
	init_ext(exts->list.array[1], &asn_DEF_AuthorityKeyIdentifier, NID_authority_key_identifier, false, &aki);

	/* Extended Key Usage */
	init_ek_ee(&eku);
	init_ext(exts->list.array[2], &asn_DEF_KeyUsage, NID_key_usage, true, &eku);

	/* CRL Distribution Points */
	init_crldp(&crldp, ee->parent->rpp.crldp);
	init_ext(exts->list.array[3], &asn_DEF_CRLDistributionPoints, NID_crl_distribution_points, false, &crldp);

	/* AIA */
	init_aia(&aia, ee->parent->uri);
	init_ext(exts->list.array[4], &asn_DEF_AuthorityInfoAccessSyntax, NID_info_access, false, &aia);

	/* SIA */
	init_sia_ee(&sia, so_uri);
	init_ext(exts->list.array[5], &asn_DEF_SubjectInfoAccessSyntax, NID_sinfo_access, false, &sia);

	/* Certificate Policies */
	init_cp(&cp);
	init_ext(exts->list.array[6], &asn_DEF_CertificatePolicies, NID_certificate_policies, true, &cp);

	/* IP Address Blocks */
	init_ext(exts->list.array[7], &asn_DEF_IPAddrBlocks, NID_ip_v2, true, &ee->ip);

	/* ASNs */
	init_ext(exts->list.array[8], &asn_DEF_ASIdentifiers, NID_asn_v2, true, &ee->asn);
}

struct rpki_certificate *
cer_new(char const *filename, struct rpki_certificate *parent)
{
	struct rpki_certificate *cer;

	cer = pzalloc(sizeof(struct rpki_certificate));
	cer_init(cer, filename, parent);

	return cer;
}

void
cer_init(struct rpki_certificate *cer, char const *filename,
    struct rpki_certificate *parent)
{
	TBSCertificate_t *tbs;

	cer->subject = filename;
	cer->keys = keys_new();
	cer->spki = pubkey2asn1(cer->keys);
	cer->parent = parent;

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
	/* tbs->issuerUniqueID: Not implemented yet */
	/* tbs->subjectUniqueID: Not implemented yet */
	/* tbs->extensions: Not implemented yet */
	init_oid(&cer->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	cer->obj.signatureAlgorithm.parameters = create_null();
	/* cer->signature: Postpone (needs all other fields ready) */

	init_ip(&cer->ip);
	init_asn(&cer->asn);
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

static void
ensure_compiled(void)
{
	if (!cer_fields)
		fields_compile(cer_metadata, &cer_fields);
}

void
cer_apply_keyvals(struct rpki_certificate *cer, struct keyvals *kvs)
{
	ensure_compiled();
	fields_apply_keyvals(cer_fields, cer, kvs);
}

static void
update_signature(Certificate_t *cer, EVP_PKEY *privkey)
{
	unsigned char tbscer[4096];
	asn_enc_rval_t rval;
	SignatureValue_t signature;

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
	init_extensions_ta(ta);
	update_signature(&ta->obj, ta->keys);
}

void
cer_finish_ca(struct rpki_certificate *ca)
{
	if (ca->parent == NULL)
		panic("CA '%s' has no parent1.", ca->subject);

	if (ca->obj.tbsCertificate.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&ca->obj.tbsCertificate.issuer, ca->parent->subject);
	}
	init_extensions_ca(ca);
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
	init_extensions_ee(ee, so_uri);
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

	ensure_compiled();
	fields_print(cer_fields, cer);
}
