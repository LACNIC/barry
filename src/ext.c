#include "ext.h"

#include "asn1.h"
#include "libcrypto.h"
#include "oid.h"

void
init_ext(Extension_t *ext, asn_TYPE_descriptor_t *td, int const oid[], bool critical, void *obj)
{
	init_oid(&ext->extnID, oid);
	ext->critical = critical ? 0xFF : 0;
	der_encode_8str(td, obj, &ext->extnValue);
}

void
init_bc(BasicConstraints_t *bc)
{
	bc->cA = 0xFF;
	bc->pathLenConstraint = NULL;
}

void
init_ski(SubjectKeyIdentifier_t *ski, SubjectPublicKeyInfo_t *spki)
{
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size, ski);
}

void
init_aki(AuthorityKeyIdentifier_t *aki, SubjectPublicKeyInfo_t *spki)
{
	aki->keyIdentifier = pzalloc(sizeof(*aki->keyIdentifier));
	hash_sha1(spki->subjectPublicKey.buf, spki->subjectPublicKey.size,
	    aki->keyIdentifier);
}

void
init_ku_ca(KeyUsage_t *ku)
{
	ku->buf = pmalloc(1);
	ku->buf[0] = 6;
	ku->size = 1;
	ku->bits_unused = 1;
}

void
init_ek_ee(KeyUsage_t *ku)
{
	ku->buf = pmalloc(1);
	ku->buf[0] = 0x80;
	ku->size = 1;
	ku->bits_unused = 7;
}

void
init_gn_uri(GeneralName_t *gn, char const *url)
{
	gn->present = GeneralName_PR_uniformResourceIdentifier;
	init_8str(&gn->choice.uniformResourceIdentifier, url);
}

void
init_crldp(CRLDistributionPoints_t *crldp, char const *url)
{
	DistributionPointName_t *dpn;

	INIT_ASN1_ARRAY(&crldp->list, 1, DistributionPoint_t);
	dpn = pzalloc(sizeof(DistributionPointName_t));
	crldp->list.array[0]->distributionPoint = dpn;
	dpn->present = DistributionPointName_PR_fullName;
	INIT_ASN1_ARRAY(&dpn->choice.fullName.list, 1, GeneralName_t);
	init_gn_uri(dpn->choice.fullName.list.array[0], url);
}

void
init_ad(AccessDescription_t *ad, const int *oid, char const *value)
{
	init_oid(&ad->accessMethod, oid);
	init_gn_uri(&ad->accessLocation, value);
}

void
init_aia(AuthorityInfoAccessSyntax_t *aia, char const *url)
{
	INIT_ASN1_ARRAY(&aia->list, 1, AccessDescription_t);
	init_ad(aia->list.array[0], OID_CA_ISSUERS, url);
}

void
init_sia_ca(SubjectInfoAccessSyntax_t *sia, char const *repo, char const *mft,
    char const *notif)
{
	unsigned int ads;

	ads = (repo ? 1 : 0) + (mft ? 1 : 0) + (notif ? 1 : 0);
	INIT_ASN1_ARRAY(&sia->list, ads, AccessDescription_t);

	ads = 0;
	if (repo)
		init_ad(sia->list.array[ads++], OID_CA_REPOSITORY, repo);
	if (mft)
		init_ad(sia->list.array[ads++], OID_SIA_RPKI_MANIFEST, mft);
	if (notif)
		init_ad(sia->list.array[ads++], OID_RPKI_NOTIFY, notif);
}

void
init_sia_ee(SubjectInfoAccessSyntax_t *sia, char const *so)
{
	INIT_ASN1_ARRAY(&sia->list, 1, AccessDescription_t);
	init_ad(sia->list.array[0], OID_SIGNED_OBJECT, so);
}

void
init_cp(CertificatePolicies_t *cp)
{
	INIT_ASN1_ARRAY(&cp->list, 1, PolicyInformation_t);
	init_oid(&cp->list.array[0]->policyIdentifier, OID_RESOURCE_POLICY);
}

void
init_ip(IPAddrBlocks_t *ip)
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
init_asn(ASIdentifiers_t *asn)
{
	ASIdOrRange_t *air;

	asn->asnum = pzalloc(sizeof(ASIdentifierChoice_t));

	asn->asnum->present = ASIdentifierChoice_PR_asIdsOrRanges;
	INIT_ASN1_ARRAY(&asn->asnum->choice.asIdsOrRanges.list, 1, ASIdOrRange_t);

	air = asn->asnum->choice.asIdsOrRanges.list.array[0];
	air->present = ASIdOrRange_PR_id;
	init_INTEGER(&air->choice.id, 123);
}
