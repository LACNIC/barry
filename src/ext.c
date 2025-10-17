#include "ext.h"

#include <errno.h>
#include <libasn1fort/ASIdOrRange.h>
#include <libasn1fort/ASIdentifierChoice.h>
#include <libasn1fort/CertificateSerialNumber.h>
#include <libasn1fort/DistributionPoint.h>
#include <libasn1fort/DistributionPointName.h>
#include <libasn1fort/Extension.h>
#include <libasn1fort/IPAddressFamily.h>
#include <libasn1fort/IPAddressOrRange.h>
#include <libasn1fort/KeyIdentifier.h>
#include <libasn1fort/PolicyInformation.h>
#include <openssl/obj_mac.h>

#include "asn1.h"
#include "cer.h"
#include "oid.h"
#include "sha.h"

struct ext_list_node *
add_extension(struct extensions *exts,
    enum ext_type type, const asn_TYPE_descriptor_t *td,
    char const *name, int nid,
    bool critical)
{
	struct ext_list_node *ext;

	pr_trace("Adding extension: %s", td->name);
	ext = pzalloc(sizeof(struct ext_list_node));
	ext->type = type;
	ext->td = td;
	ext->name = pstrdup(name);
	init_oid(&ext->extnID, nid);
	ext->critical = critical ? 0xFF : 0;
	STAILQ_INSERT_TAIL(exts, ext, hook);

	return ext;
}

static void
add_bc_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);

	value = field_add(parent, "extnValue", &ft_obj, &ext->v, 0);
	field_add(value, "cA", &ft_bool, &ext->v.bc.cA, 0);
	field_add(value, "pathLenConstraint", &ft_int,
	    &ext->v.bc.pathLenConstraint, sizeof(INTEGER_t));
}

void
exts_add_bc(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_BC, &asn_DEF_BasicConstraints, name,
	    NID_basic_constraints, true);
	ext->v.bc.cA = 0xFF;

	add_bc_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_ski_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_8str, &ext->v, 0);
}

void
exts_add_ski(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_SKI, &asn_DEF_SubjectKeyIdentifier, name,
	    NID_subject_key_identifier, false);

	add_ski_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_aki_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	value = field_add(parent, "extnValue", &ft_obj, &ext->v, 0);

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
exts_add_aki(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_AKI, &asn_DEF_AuthorityKeyIdentifier,
	    name, NID_authority_key_identifier, false);

	add_aki_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_ku_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_bitstr, &ext->v.ku, 0);
}

void
exts_add_ku(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_KU, &asn_DEF_KeyUsage, name,
	    NID_key_usage, true);

	add_ku_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_crldp_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.crldp, 0	TODO not implemented yet
}

void
exts_add_crldp(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_CRLDP, &asn_DEF_CRLDistributionPoints,
	    name, NID_crl_distribution_points, false);

	add_crldp_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static struct field *
add_ia_fields(struct field *parent, struct ext_list_node *ext, void *extobj)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	return field_add(parent, "extnValue", &ft_ads, extobj, 0);
}

static void
init_ad(AccessDescription_t *ad, struct field *extnValuef,
    int nid, char const *name)
{
	struct field *adf;

	init_oid(&ad->accessMethod, nid);
	ad->accessLocation.present = GeneralName_PR_uniformResourceIdentifier;

	adf = field_add(extnValuef, name, &ft_obj, ad, 0);
	field_add(adf, "accessMethod", &ft_oid, &ad->accessMethod, 0);
	field_add_gname(adf, "accessLocation", &ad->accessLocation);
}

void
exts_add_aia(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;
	struct field *aiaf;
	struct field *extnValuef;

	ext = add_extension(exts,
	    EXT_AIA, &asn_DEF_AuthorityInfoAccessSyntax,
	    name, NID_info_access,
	    false);
	INIT_ASN1_ARRAY(&ext->v.aia.list, 1, AccessDescription_t);

	aiaf = field_add(extsf, name, &ft_obj, &ext->v, 0);
	extnValuef = add_ia_fields(aiaf, ext, &ext->v.aia);

	init_ad(ext->v.aia.list.array[0], extnValuef, NID_ad_ca_issuers, "0");
}

int
sia_ca_defaults(SubjectInfoAccessSyntax_t *sia, struct field *evf)
{
	extern char const *rrdp_uri;

	if (sia == NULL)
		goto end;

	init_ad(sia->list.array[0], evf, NID_caRepository, "0");
	init_ad(sia->list.array[1], evf, NID_rpkiManifest, "1");
	// TODO (test) check no default rpkiNotify is created if --rrdp-uri is missing
	if (rrdp_uri)
		init_ad(sia->list.array[2], evf, NID_rpkiNotify, "2");
end:	return rrdp_uri ? 3 : 2;
}

int
sia_ee_defaults(SubjectInfoAccessSyntax_t *sia, struct field *evf)
{
	if (sia == NULL)
		return 1;

	init_ad(sia->list.array[0], evf, NID_signedObject, "0");
	return 1;
}

int
sia_empty_defaults(SubjectInfoAccessSyntax_t *sia, struct field *evf)
{
	return 0;
}

void
exts_add_sia(struct extensions *exts, char const *name, struct field *extsf,
    sia_defaults defaults)
{
	struct ext_list_node *ext;
	int adn;
	struct field *siaf;
	struct field *extnValuef;

	ext = add_extension(exts,
	    EXT_SIA, &asn_DEF_SubjectInfoAccessSyntax,
	    name, NID_sinfo_access,
	    false);
	adn = defaults(NULL, NULL);
	INIT_ASN1_ARRAY(&ext->v.sia.list, adn, AccessDescription_t);

	siaf = field_add(extsf, name, &ft_obj, &ext->v, 0);
	extnValuef = add_ia_fields(siaf, ext, &ext->v.sia);

	defaults(&ext->v.sia, extnValuef);
}

static void
add_cp_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
//	"extnValue", &ext->v.cp, 0	TODO not implemented yet
}

void
exts_add_cp(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_CP, &asn_DEF_CertificatePolicies, name,
	    NID_certificate_policies, true);

	add_cp_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_ip_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_ip_cer, &ext->v.ip, 0);
}

void
exts_add_ip(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_IP, &asn_DEF_IPAddrBlocks, name,
	    NID_sbgp_ipAddrBlock, true);

	add_ip_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_asn_fields(struct field *parent, struct ext_list_node *ext)
{
	struct field *value;

	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);

	value = field_add(parent, "extnValue", &ft_obj, &ext->v, 0);
	field_add(value, "asnum", &ft_asn_cer, &ext->v.asn.asnum,
	    sizeof(ASIdentifierChoice_t));
	field_add(value, "rdi", &ft_asn_cer, &ext->v.asn.rdi,
	    sizeof(ASIdentifierChoice_t));
}

void
exts_add_asn(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_ASN, &asn_DEF_ASIdentifiers, name,
	    NID_sbgp_autonomousSysNum, true);

	add_asn_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
}

static void
add_crln_fields(struct field *parent, struct ext_list_node *ext)
{
	field_add(parent, "extnID", &ft_oid, &ext->extnID, 0);
	field_add(parent, "critical", &ft_bool, &ext->critical, 0);
	field_add(parent, "extnValue", &ft_int, &ext->v.crln, 0);
}

void
exts_add_crln(struct extensions *exts, char const *name, struct field *extsf)
{
	struct ext_list_node *ext;

	ext = add_extension(exts, EXT_CRLN, &asn_DEF_CRLNumber, name,
	    NID_crl_number, false);
	init_INTEGER(&ext->v.crln, 1);

	add_crln_fields(field_add(extsf, name, &ft_obj, &ext->v, 0), ext);
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

static bool
is_accessLocation_overridden(struct field *extnValuef, size_t extn,
    AccessDescription_t *ad)
{
	struct field *extnf;

	extnf = fields_find_n(extnValuef, extn);
	if (fields_overridden(extnf, "accessLocation.value"))
		return true;

	if (ad->accessLocation.present == GeneralName_PR_NOTHING)
		return false;
	if (ad->accessLocation.present != GeneralName_PR_uniformResourceIdentifier)
		/*
		 * Type overridden but value unset.
		 * No idea what the user wants, but it more or less
		 * means the value is also overridden.
		 */
		return true;

	return false;
}

void
ext_finish_aia(AuthorityInfoAccessSyntax_t *aia, struct field *extnValuef,
    char const *caIssuers)
{
	AccessDescription_t *ad;
	int i;

	pr_trace("Autocompleting AIA");

	if (!caIssuers)
		return;

	for (i = 0; i < aia->list.count; i++) {
		ad = aia->list.array[i];

		if (is_accessLocation_overridden(extnValuef, i, ad))
			continue;

		if (oid_is_caIssuers(&ad->accessMethod))
			finish_gn_uri(&ad->accessLocation, caIssuers);
	}
}

void
ext_finish_sia(SubjectInfoAccessSyntax_t *sia, struct field *extnValuef,
    struct rpki_certificate *cer, char const *so)
{
	struct rpp *rpp;
	AccessDescription_t *ad;
	char const *value;
	size_t i;

	pr_trace("Autocompleting SIA");

	rpp = cer ? &cer->rpp : NULL;

	for (i = 0; i < sia->list.count; i++) {
		ad = sia->list.array[i];

		if (is_accessLocation_overridden(extnValuef, i, ad))
			continue;

		value = NULL;
		if (oid_is_caRepository(&ad->accessMethod))
			value = rpp ? rpp->uri : NULL;
		else if (oid_is_rpkiManifest(&ad->accessMethod))
			value = cer_rpkiManifest(cer);
		else if (oid_is_rpkiNotify(&ad->accessMethod))
			value = rpp ? rpp->notification : NULL;
		else if (oid_is_signedObject(&ad->accessMethod))
			value = so;
		if (value)
			finish_gn_uri(&ad->accessLocation, value);
	}
}

void
ext_finish_cp(CertificatePolicies_t *cp)
{
	pr_trace("Autocompleting CP");
	INIT_ASN1_ARRAY(&cp->list, 1, PolicyInformation_t);
	init_oid(&cp->list.array[0]->policyIdentifier, NID_ipAddr_asNumber);
}

static uint8_t *
get_serials(struct rpki_tree_node *node)
{
	uint8_t *buf;
	struct rpki_tree_node *cursor;
	unsigned int n;

	if (node->depth == 0)
		return NULL;

	buf = pcalloc(node->depth, sizeof(uint8_t));

	cursor = node;
	for (n = 0; n < node->depth; n++) {
		buf[n] = cursor->serial & 0xFFu;
		cursor = cursor->parent;
	}

	return buf;
}

static void
serials2bitstr(uint8_t *serials, size_t addrn,
    BIT_STRING_t *bs, unsigned int max)
{
	size_t i;

	if (addrn == 0)
		return;

	bs->size = (addrn < max) ? addrn : max;
	bs->buf = pmalloc(bs->size);
	for (i = 0; i < bs->size; i++)
		bs->buf[i] = serials[addrn - i - 1];
}

void
ext_finish_ip(IPAddrBlocks_t *ip, struct rpki_tree_node *node)
{
	OCTET_STRING_t *iaf;
	IPAddressChoice_t *iac;
	IPAddressOrRange_t *iar;
	uint8_t *serials;

	pr_trace("Autocompleting IP");

	INIT_ASN1_ARRAY(&ip->list, 2, IPAddressFamily_t);

	/* IPv4 */
	iaf = &ip->list.array[0]->addressFamily;
	iaf->size = 2;
	iaf->buf = pmalloc(iaf->size);
	iaf->buf[0] = 0;
	iaf->buf[1] = 1;

	/* IPv6 */
	iaf = &ip->list.array[1]->addressFamily;
	iaf->size = 2;
	iaf->buf = pmalloc(iaf->size);
	iaf->buf[0] = 0;
	iaf->buf[1] = 2;

	if (node->type == FT_TA || node->type == FT_CER || node->type == FT_ROA) {
		serials = get_serials(node);

		/* IPv4 */
		iac = &ip->list.array[0]->ipAddressChoice;
		iac->present = IPAddressChoice_PR_addressesOrRanges;
		INIT_ASN1_ARRAY(&iac->choice.addressesOrRanges.list,
		    1, IPAddressOrRange_t);
		iar = iac->choice.addressesOrRanges.list.array[0];
		iar->present = IPAddressOrRange_PR_addressPrefix;
		serials2bitstr(serials, node->depth,
		    &iar->choice.addressPrefix, 4);

		/* IPv6 */
		iac = &ip->list.array[1]->ipAddressChoice;
		iac->present = IPAddressChoice_PR_addressesOrRanges;
		INIT_ASN1_ARRAY(&iac->choice.addressesOrRanges.list,
		    1, IPAddressOrRange_t);
		iar = iac->choice.addressesOrRanges.list.array[0];
		iar->present = IPAddressOrRange_PR_addressPrefix;
		serials2bitstr(serials, node->depth,
		    &iar->choice.addressPrefix, 16);

		free(serials);

	} else {
		/* IPv4 */
		iac = &ip->list.array[0]->ipAddressChoice;
		iac->present = IPAddressChoice_PR_inherit;

		/* IPv6 */
		iac = &ip->list.array[1]->ipAddressChoice;
		iac->present = IPAddressChoice_PR_inherit;
	}
}

static void
serials2asn(uint8_t *serials, size_t addrn, INTEGER_t *asn, uint8_t empty)
{
	unsigned long val;

	val = (((addrn > 0) ? (serials[addrn - 1] & 0xFFu) : empty) << 24u)
	    | (((addrn > 1) ? (serials[addrn - 2] & 0xFFu) : empty) << 16u)
	    | (((addrn > 2) ? (serials[addrn - 3] & 0xFFu) : empty) <<  8u)
	    | (((addrn > 3) ? (serials[addrn - 4] & 0xFFu) : empty) <<  0u);

	if (asn_ulong2INTEGER(asn, val) < 0)
		panic("Cannot convert %lu to INTEGER: %s", val, strerror(errno));
}

void
ext_finish_asn(ASIdentifiers_t *asn, struct rpki_tree_node *node)
{
	uint8_t *serials;
	ASIdOrRange_t *air;

	pr_trace("Autocompleting ASN");

	asn->asnum = pzalloc(sizeof(ASIdentifierChoice_t));

	if (node->type == FT_TA || node->type == FT_CER) {
		asn->asnum->present = ASIdentifierChoice_PR_asIdsOrRanges;
		INIT_ASN1_ARRAY(&asn->asnum->choice.asIdsOrRanges.list,
		    1, ASIdOrRange_t);

		air = asn->asnum->choice.asIdsOrRanges.list.array[0];

		serials = get_serials(node);
		if (node->depth < 4) {
			air->present = ASIdOrRange_PR_range;
			serials2asn(serials, node->depth, &air->choice.range.min, 0);
			serials2asn(serials, node->depth, &air->choice.range.max, 0xFFu);
		} else {
			air->present = ASIdOrRange_PR_id;
			serials2asn(serials, node->depth, &air->choice.id, 0);
		}
		free(serials);

	} else {
		asn->asnum->present = ASIdentifierChoice_PR_inherit;
	}
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
