#include "ext.h"

#include "asn1.h"
#include "libcrypto.h"
#include "oid.h"

struct ext_list_node *
add_extension(struct extensions *exts, int nid, bool critical,
    enum ext_type type, const asn_TYPE_descriptor_t *td)
{
	struct ext_list_node *ext;

	pr_trace("Adding extension: %s", td->name);
	ext = pzalloc(sizeof(struct ext_list_node));
	init_oid(&ext->extnID, nid);
	ext->critical = critical ? 0xFF : 0;
	ext->type = type;
	ext->td = td;
	STAILQ_INSERT_TAIL(exts, ext, hook);

	return ext;
}

static void
add_bc_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);

	value = field_add_static(parent, "extnValue");
	field_add(value, "cA", &ft_bool, &ext->v.bc.cA, 0);
	field_add(value, "pathLenConstraint", &ft_int,
	    &ext->v.bc.pathLenConstraint, sizeof(INTEGER_t));
}

void
exts_add_bc(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_basic_constraints, true, EXT_BC,
	    &asn_DEF_BasicConstraints);
	ext->v.bc.cA = 0xFF;

	add_bc_fields(field_add_static(parent, "bc"), ext);
	add_bc_fields(field_add_static_n(parent, extn), ext);
}

static void
add_ski_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_8str, &ext->v.ski, 0);
}

void
exts_add_ski(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_subject_key_identifier, false, EXT_SKI,
	    &asn_DEF_SubjectKeyIdentifier);

	add_ski_fields(field_add_static(parent, "ski"), ext);
	add_ski_fields(field_add_static_n(parent, extn), ext);
}

static void
add_aki_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);

	value = field_add_static(parent, "extnValue");
	field_add(value, "keyIdentifier", &ft_8str,
	    &ext->v.aki.keyIdentifier,
	    sizeof(KeyIdentifier_t));
//	TODO not implemented yet
//	field_add_leaf(value, "authorityCertIssuer", ,
//	    &ext->v.aki.authorityCertIssuer,
//	    sizeof(GeneralNames_t));
	field_add(value, "authorityCertSerialNumber", &ft_int,
	    &ext->v.aki.authorityCertSerialNumber,
	    sizeof(CertificateSerialNumber_t));
}

void
exts_add_aki(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_authority_key_identifier, false, EXT_AKI,
	    &asn_DEF_AuthorityKeyIdentifier);

	add_aki_fields(field_add_static(parent, "aki"), ext);
	add_aki_fields(field_add_static_n(parent, extn), ext);
}

static void
add_ku_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_bitstr, &ext->v.ku, 0);
}

void
exts_add_ku(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_key_usage, true, EXT_KU,
	    &asn_DEF_KeyUsage);

	add_ku_fields(field_add_static(parent, "ku"), ext);
	add_ku_fields(field_add_static_n(parent, extn), ext);
}

static void
add_crldp_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.crldp, 0	TODO not implemented yet
}

void
exts_add_crldp(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_crl_distribution_points, false, EXT_CRLDP,
	    &asn_DEF_CRLDistributionPoints);

	add_crldp_fields(field_add_static(parent, "crldp"), ext);
	add_crldp_fields(field_add_static_n(parent, extn), ext);
}

static void
add_aia_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.aia, 0	TODO not implemented yet
}

void
exts_add_aia(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_info_access, false, EXT_AIA,
	    &asn_DEF_AuthorityInfoAccessSyntax);

	add_aia_fields(field_add_static(parent, "aia"), ext);
	add_aia_fields(field_add_static_n(parent, extn), ext);
}

static void
add_sia_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.sia, 0	TODO not implemented yet
}

void
exts_add_sia(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_sinfo_access, false, EXT_SIA,
	    &asn_DEF_SubjectInfoAccessSyntax);

	add_sia_fields(field_add_static(parent, "sia"), ext);
	add_sia_fields(field_add_static_n(parent, extn), ext);
}

static void
add_cp_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.cp, 0	TODO not implemented yet
}

void
exts_add_cp(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_certificate_policies, true, EXT_CP,
	    &asn_DEF_CertificatePolicies);

	add_cp_fields(field_add_static(parent, "cp"), ext);
	add_cp_fields(field_add_static_n(parent, extn), ext);
}

static void
add_ip_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_ip_cer, &ext->v.ip, 0);
}

void
exts_add_ip(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_sbgp_ipAddrBlockv2, true, EXT_IP,
	    &asn_DEF_IPAddrBlocks);

	add_ip_fields(field_add_static(parent, "ip"), ext);
	add_ip_fields(field_add_static_n(parent, extn), ext);
}

static void
add_asn_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);

	value = field_add_static(parent, "extnValue");
	field_add(value, "asnum", &ft_asn_cer, &ext->v.asn.asnum,
	    sizeof(ASIdentifierChoice_t));
	field_add(value, "rdi", &ft_asn_cer, &ext->v.asn.rdi,
	    sizeof(ASIdentifierChoice_t));
}

void
exts_add_asn(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_sbgp_autonomousSysNumv2, true, EXT_ASN,
	    &asn_DEF_ASIdentifiers);

	add_asn_fields(field_add_static(parent, "asn"), ext);
	add_asn_fields(field_add_static_n(parent, extn), ext);
}

static void
add_crln_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_int, &ext->v.crln, 0);
}

void
exts_add_crln(struct extensions *exts, size_t extn, struct field *parent)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, NID_crl_number, false, EXT_CRLN,
	    &asn_DEF_CRLNumber);
	init_INTEGER(&ext->v.crln, 1);

	add_crln_fields(field_add_static(parent, "crln"), ext);
	add_crln_fields(field_add_static_n(parent, extn), ext);
}

void
ext_finish_ski(SubjectKeyIdentifier_t *ski, SubjectPublicKeyInfo_t *spki)
{
	pr_trace("Autocompleting SKI");
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size, ski);
}

void
ext_finish_aki(AuthorityKeyIdentifier_t *aki, SubjectPublicKeyInfo_t *spki)
{
	pr_trace("Autocompleting AKI");
	aki->keyIdentifier = pzalloc(sizeof(*aki->keyIdentifier));
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size,
	    aki->keyIdentifier);
}

void
ext_finish_ku(KeyUsage_t *ku, enum cer_type type)
{
	pr_trace("Autocompleting KU");

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
ext_finish_crldp(CRLDistributionPoints_t *crldp, char const *url)
{
	DistributionPointName_t *dpn;

	pr_trace("Autocompleting CRLDP");

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
ext_finish_aia(AuthorityInfoAccessSyntax_t *aia, char const *url)
{
	pr_trace("Autocompleting AIA");
	INIT_ASN1_ARRAY(&aia->list, 1, AccessDescription_t);
	finish_ad(aia->list.array[0], NID_ad_ca_issuers, url);
}

void
ext_finish_sia_ca(SubjectInfoAccessSyntax_t *sia, char const *repo,
    char const *mft, char const *notif)
{
	unsigned int ads;

	pr_trace("Autocompleting SIA (CA variant)");

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
ext_finish_sia_ee(SubjectInfoAccessSyntax_t *sia, char const *so)
{
	pr_trace("Autocompleting AIA (EE variant)");
	INIT_ASN1_ARRAY(&sia->list, 1, AccessDescription_t);
	finish_ad(sia->list.array[0], NID_signedObject, so);
}

void
ext_finish_cp(CertificatePolicies_t *cp)
{
	pr_trace("Autocompleting CP");
	INIT_ASN1_ARRAY(&cp->list, 1, PolicyInformation_t);
	init_oid(&cp->list.array[0]->policyIdentifier, NID_ipAddr_asNumberv2);
}

void
ext_finish_ip(IPAddrBlocks_t *ip)
{
	IPAddressFamily_t *iaf;
	IPAddressOrRange_t *iar;

	pr_trace("Autocompleting IP");

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
ext_finish_asn(ASIdentifiers_t *asn)
{
	ASIdOrRange_t *air;

	pr_trace("Autocompleting ASN");

	asn->asnum = pzalloc(sizeof(ASIdentifierChoice_t));

	asn->asnum->present = ASIdentifierChoice_PR_asIdsOrRanges;
	INIT_ASN1_ARRAY(&asn->asnum->choice.asIdsOrRanges.list, 1, ASIdOrRange_t);

	air = asn->asnum->choice.asIdsOrRanges.list.array[0];
	air->present = ASIdOrRange_PR_id;
	init_INTEGER(&air->choice.id, 123);
}

bool
ext_field_set(struct field *fields, char const *name, unsigned int extn,
    char const *suffix)
{
	char key[FIELD_MAXLEN];
	struct field *field;

	psnprintf(key, FIELD_MAXLEN, "%s.%s", name, suffix);
	field = fields_find(fields, key);
	if (field && field->overridden)
		return true;

	psnprintf(key, FIELD_MAXLEN, "%u.%s", extn, suffix);
	field = fields_find(fields, key);
	return field && field->overridden;
}

void
ext_compile(struct extensions *src, Extensions_t **_dst)
{
	Extensions_t *dst;
	Extension_t *ext;
	struct ext_list_node *node;
	size_t n;

	n = 0;
	STAILQ_FOREACH(node, src, hook)
		n++;

	dst = pmalloc(sizeof(Extensions_t));
	INIT_ASN1_ARRAY(&dst->list, n, Extension_t);

	n = 0;
	STAILQ_FOREACH(node, src, hook) {
		ext = dst->list.array[n++];
		ext->extnID = node->extnID;
		ext->critical = node->critical;
		der_encode_8str(node->td, &node->v, &ext->extnValue);
	}

	*_dst = dst;
}
