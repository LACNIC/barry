#include "ext.h"

#include "asn1.h"
#include "libcrypto.h"
#include "oid.h"

struct ext_list_node *
add_new_extension(struct extensions *exts, enum ext_type type,
    const asn_TYPE_descriptor_t *td)
{
	struct ext_list_node *ext;

	pr_trace("Adding extension: %s", td->name);
	ext = pzalloc(sizeof(struct ext_list_node));
	ext->type = type;
	ext->td = td;
	STAILQ_INSERT_TAIL(&exts->list, ext, hook);

	return ext;
}

static void
init_ext(Extension_t *ext, int nid, bool critical,
    struct field *fields, char const *ctx, char const *name, size_t extn)
{
	init_oid(&ext->extnID, nid);
	ext->critical = critical ? 0xFF : 0;

	fields_add_ext(fields, ctx, name, extn, "extnID", &ft_oid, &ext->extnID, 0);
	fields_add_ext(fields, ctx, name, extn, "critical", &ft_bool, &ext->critical, 0);
}

void
exts_add_bc(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_BC, &asn_DEF_BasicConstraints);
	ext->v.bc.cA = 0xFF;

	init_ext(exts->array.list.array[extn], NID_basic_constraints, true, fields, ctx, "bc", extn);
	fields_add_ext(fields, ctx, "bc", extn, "extnValue.cA", &ft_bool, &ext->v.bc.cA, 0);
	fields_add_ext(fields, ctx, "bc", extn, "extnValue.pathLenConstraint", &ft_int, &ext->v.bc.pathLenConstraint, sizeof(INTEGER_t));
}

void
exts_add_ski(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_SKI, &asn_DEF_SubjectKeyIdentifier);

	init_ext(exts->array.list.array[extn], NID_subject_key_identifier, false, fields, ctx, "ski", extn);
	fields_add_ext(fields, ctx, "ski", extn, "extnValue", &ft_8str, &ext->v.ski, 0);
}

void
exts_add_aki(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_AKI, &asn_DEF_AuthorityKeyIdentifier);

	init_ext(exts->array.list.array[extn], NID_authority_key_identifier, false, fields, ctx, "aki", extn);
	fields_add_ext(fields,
	    ctx, "aki", extn, "extnValue.keyIdentifier",
	    &ft_8str, &ext->v.aki.keyIdentifier, sizeof(KeyIdentifier_t));
//	TODO not implemented yet
//	fields_add_ext(fields,
//	    ctx, "aki", extn, "extnValue.authorityCertIssuer", );
	fields_add_ext(fields,
	    ctx, "aki", extn, "extnValue.authorityCertSerialNumber",
	    &ft_int, &ext->v.aki.authorityCertSerialNumber,
	    sizeof(CertificateSerialNumber_t));
}

void
exts_add_ku(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_KU, &asn_DEF_KeyUsage);

	init_ext(exts->array.list.array[extn], NID_key_usage, true, fields, ctx, "ku", extn);
	fields_add_ext(fields, ctx, "ku", extn, "extnValue", &ft_bitstr, &ext->v.ku, 0);
}

void
exts_add_crldp(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	add_new_extension(exts, EXT_CRLDP, &asn_DEF_CRLDistributionPoints);

	init_ext(exts->array.list.array[extn], NID_crl_distribution_points, false, fields, ctx, "crldp", extn);
//	fields_add_ext(fields, ctx, "crldp", extn, "extnValue", &, &ext->v.crldp, 0); TODO not implemented yet
}

void
exts_add_aia(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	add_new_extension(exts, EXT_AIA, &asn_DEF_AuthorityInfoAccessSyntax);

	init_ext(exts->array.list.array[extn], NID_info_access, false, fields, ctx, "aia", extn);
//	fields_add_ext(fields, ctx, "aia", extn, "extnValue", &, &ext->v.aia, 0); TODO not implemented yet
}

void
exts_add_sia(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	add_new_extension(exts, EXT_SIA, &asn_DEF_SubjectInfoAccessSyntax);

	init_ext(exts->array.list.array[extn], NID_sinfo_access, false, fields, ctx, "sia", extn);
//	fields_add_ext(fields, ctx, "sia", extn, "extnValue", &, &ext->v.sia, 0); TODO not implemented yet
}

void
exts_add_cp(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	add_new_extension(exts, EXT_CP, &asn_DEF_CertificatePolicies);

	init_ext(exts->array.list.array[extn], NID_certificate_policies, true, fields, ctx, "cp", extn);
//	fields_add_ext(fields, ctx, "cp", extn, "extnValue", &, &ext->v.cp, 0); TODO not implemented yet
}

void
exts_add_ip(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_IP, &asn_DEF_IPAddrBlocks);

	init_ext(exts->array.list.array[extn], NID_sbgp_ipAddrBlockv2, true, fields, ctx, "ip", extn);
	fields_add_ext(fields, ctx, "ip", extn, "extnValue", &ft_ip_cer, &ext->v.ip, 0);
}

void
exts_add_asn(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_ASN, &asn_DEF_ASIdentifiers);

	init_ext(exts->array.list.array[extn], NID_sbgp_autonomousSysNumv2, true, fields, ctx, "asn", extn);
	fields_add_ext(fields, ctx, "asn", extn, "extnValue.asnum", &ft_asn_cer, &ext->v.asn.asnum, sizeof(ASIdentifierChoice_t));
	fields_add_ext(fields, ctx, "asn", extn, "extnValue.rdi", &ft_asn_cer, &ext->v.asn.rdi, sizeof(ASIdentifierChoice_t));
}

void
exts_add_crln(struct extensions *exts, size_t extn, struct field *fields, char const *ctx)
{
	struct ext_list_node *ext;

	ext = add_new_extension(exts, EXT_CRLN, &asn_DEF_CRLNumber);
	init_INTEGER(&ext->v.crln, 1);

	init_ext(exts->array.list.array[extn], NID_crl_number, false, fields, ctx, "crln", extn);
	fields_add_ext(fields, ctx, "crln", extn, "extnValue", &ft_int, &ext->v.crln, 0);
}

void
finish_ski(SubjectKeyIdentifier_t *ski, SubjectPublicKeyInfo_t *spki)
{
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size, ski);
}

void
finish_aki(AuthorityKeyIdentifier_t *aki, SubjectPublicKeyInfo_t *spki)
{
	aki->keyIdentifier = pzalloc(sizeof(*aki->keyIdentifier));
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size,
	    aki->keyIdentifier);
}

void
finish_ku(KeyUsage_t *ku, enum cer_type type)
{
	ku->buf = pmalloc(1);
	ku->size = 1;

	switch (type) {
	case CT_TA:
	case CT_CA:
		ku->buf[0] = 0x06;
		ku->bits_unused = 1;
		break;
	case CT_EE:
		ku->buf[0] = 0x80;
		ku->bits_unused = 7;
		break;
	}
}

static void
finish_gn_uri(GeneralName_t *gn, char const *url)
{
	gn->present = GeneralName_PR_uniformResourceIdentifier;
	init_8str(&gn->choice.uniformResourceIdentifier, url);
}

void
finish_crldp(CRLDistributionPoints_t *crldp, char const *url)
{
	DistributionPointName_t *dpn;

	INIT_ASN1_ARRAY(&crldp->list, 1, DistributionPoint_t);
	dpn = pzalloc(sizeof(DistributionPointName_t));
	crldp->list.array[0]->distributionPoint = dpn;
	dpn->present = DistributionPointName_PR_fullName;
	INIT_ASN1_ARRAY(&dpn->choice.fullName.list, 1, GeneralName_t);
	finish_gn_uri(dpn->choice.fullName.list.array[0], url);
}

static void
finish_ad(AccessDescription_t *ad, int nid, char const *value)
{
	init_oid(&ad->accessMethod, nid);
	finish_gn_uri(&ad->accessLocation, value);
}

void
finish_aia(AuthorityInfoAccessSyntax_t *aia, char const *url)
{
	INIT_ASN1_ARRAY(&aia->list, 1, AccessDescription_t);
	finish_ad(aia->list.array[0], NID_ad_ca_issuers, url);
}

void
finish_sia_ca(SubjectInfoAccessSyntax_t *sia, char const *repo, char const *mft,
    char const *notif)
{
	unsigned int ads;

	ads = (repo ? 1 : 0) + (mft ? 1 : 0) + (notif ? 1 : 0);
	INIT_ASN1_ARRAY(&sia->list, ads, AccessDescription_t);

	ads = 0;
	if (repo)
		finish_ad(sia->list.array[ads++], NID_caRepository, repo);
	if (mft)
		finish_ad(sia->list.array[ads++], NID_rpkiManifest, mft);
	if (notif)
		finish_ad(sia->list.array[ads++], NID_rpkiNotify, notif);
}

void
finish_sia_ee(SubjectInfoAccessSyntax_t *sia, char const *so)
{
	INIT_ASN1_ARRAY(&sia->list, 1, AccessDescription_t);
	finish_ad(sia->list.array[0], NID_signedObject, so);
}

void
finish_cp(CertificatePolicies_t *cp)
{
	INIT_ASN1_ARRAY(&cp->list, 1, PolicyInformation_t);
	init_oid(&cp->list.array[0]->policyIdentifier, NID_ipAddr_asNumberv2);
}

void
finish_ip(IPAddrBlocks_t *ip)
{
	IPAddressFamily_t *iaf;
	IPAddressOrRange_t *iar;

	INIT_ASN1_ARRAY(&ip->list, 1, IPAddressFamily_t);

	iaf = ip->list.array[0];
	iaf->addressFamily.size = 2;
	iaf->addressFamily.buf = pmalloc(iaf->addressFamily.size);
	iaf->addressFamily.buf[0] = 0;
	iaf->addressFamily.buf[1] = 1;

	iaf->ipAddressChoice.present = IPAddressChoice_PR_addressesOrRanges;
	INIT_ASN1_ARRAY(&iaf->ipAddressChoice.choice.addressesOrRanges.list, 1, IPAddressOrRange_t);

	iar = iaf->ipAddressChoice.choice.addressesOrRanges.list.array[0];
	iar->present = IPAddressOrRange_PR_addressPrefix;
	iar->choice.addressPrefix.size = 3;
	iar->choice.addressPrefix.buf = pmalloc(iar->choice.addressPrefix.size);
	iar->choice.addressPrefix.buf[0] = 192;
	iar->choice.addressPrefix.buf[1] = 0;
	iar->choice.addressPrefix.buf[2] = 2;
}

void
finish_asn(ASIdentifiers_t *asn)
{
	ASIdOrRange_t *air;

	asn->asnum = pzalloc(sizeof(ASIdentifierChoice_t));

	asn->asnum->present = ASIdentifierChoice_PR_asIdsOrRanges;
	INIT_ASN1_ARRAY(&asn->asnum->choice.asIdsOrRanges.list, 1, ASIdOrRange_t);

	air = asn->asnum->choice.asIdsOrRanges.list.array[0];
	air->present = ASIdOrRange_PR_id;
	init_INTEGER(&air->choice.id, 123);
}
