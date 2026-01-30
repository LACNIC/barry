#include "roa.h"

#include <libasn1fort/ROAIPAddress.h>
#include <libasn1fort/ROAIPAddressFamily.h>

#include "asn1.h"

struct signed_object *
roa_new(struct rpki_tree_node *node)
{
	struct signed_object *so;
	RouteOriginAttestation_t *roa;
	struct field *eContent;

	so = signed_object_new(node, NID_id_ct_routeOriginAuthz, &eContent);
	roa = &so->obj.roa;

	roa->version = intmax2INTEGER(0);
	field_add(eContent, "version", &ft_int, &roa->version, sizeof(INTEGER_t));

	init_INTEGER(&roa->asId, 1234);
	field_add(eContent, "asId", &ft_int, &roa->asId, 0);

	INIT_ASN1_ARRAY(&roa->ipAddrBlocks.list, 1, ROAIPAddressFamily_t);
	field_add(eContent, "ipAddrBlocks", &ft_ip_roa, &roa->ipAddrBlocks, 0);

	return so;
}

static bool
OCTET_STRING_cmp(OCTET_STRING_t *str1, OCTET_STRING_t *str2)
{
	return OCTET_STRING_compare(&asn_DEF_OCTET_STRING, str1, str2) == 0;
}

static IPAddressFamily_t *
find_inheritor(struct rpki_certificate *cer, OCTET_STRING_t *af)
{
	struct rpki_tree_node *node;
	struct ext_list_node *ext;
	IPAddressFamily_t *iaf;
	bool has_resources;
	int i;

	for (node = cer->meta->node->parent; node != NULL; node = node->parent) {
		if (!IS_CER(node->type))
			return NULL;

		ext = cer_ext(node->obj, EXT_IP);
		if (!ext)
			return NULL;

		has_resources = false;
		for (i = 0; i < ext->v.ip.list.count; i++) {
			iaf = ext->v.ip.list.array[i];

			if (OCTET_STRING_cmp(&iaf->addressFamily, af) == 0) {
				switch (iaf->ipAddressChoice.present) {
				case IPAddressChoice_PR_addressesOrRanges:
					return iaf;
				case IPAddressChoice_PR_inherit:
					has_resources = true;
					break;
				case IPAddressChoice_PR_NOTHING:
					break;
				}
			}
		}
		if (!has_resources)
			return NULL;
	}

	return NULL;
}

static void
ior2ria(IPAddressOrRange_t *ior, ROAIPAddress_t *ria)
{
	switch (ior->present) {
	case IPAddressOrRange_PR_addressPrefix:
		ria->address = ior->choice.addressPrefix;
		break;
	case IPAddressOrRange_PR_addressRange:
		ria->address = ior->choice.addressRange.min;
		break;
	case IPAddressOrRange_PR_NOTHING:
		panic("Undefined IPAddressOrRange.");
	}
}

static void
finish_addrs(struct signed_object *so)
{
	struct field *rootf;
	struct ext_list_node *ext;

	IPAddressFamily_t *iaf; /* src */
	ROAIPAddressFamily_t *riaf; /* dst */

	struct IPAddressChoice__addressesOrRanges *aor;

	IPAddressOrRange_t *ior; /* src */
	ROAIPAddress_t *ria; /* dst */

	int i, j;

	rootf = fields_find(so->objf,
	    "content.encapContentInfo.eContent.ipAddrBlocks");
	if (rootf && rootf->overridden)
		return;

	ext = cer_ext(&so->ee, EXT_IP);
	if (!ext)
		return;

	INIT_ASN1_ARRAY(&so->obj.roa.ipAddrBlocks.list, ext->v.ip.list.count,
	    ROAIPAddressFamily_t);

	for (i = 0; i < ext->v.ip.list.count; i++) {
		iaf = ext->v.ip.list.array[i];
		riaf = so->obj.roa.ipAddrBlocks.list.array[i];

		riaf->addressFamily = iaf->addressFamily;

		switch (iaf->ipAddressChoice.present) {
		case IPAddressChoice_PR_inherit:
			iaf = find_inheritor(&so->ee, &iaf->addressFamily);
			if (!iaf)
				break;
			/* No break */

		case IPAddressChoice_PR_addressesOrRanges:
			aor = &iaf->ipAddressChoice.choice.addressesOrRanges;
			INIT_ASN1_ARRAY(&riaf->addresses.list, aor->list.count,
			    ROAIPAddress_t);

			for (j = 0; j < aor->list.count; j++) {
				ior = aor->list.array[j];
				ria = riaf->addresses.list.array[j];
				ior2ria(ior, ria);
			}

			break;

		case IPAddressChoice_PR_NOTHING:
			break;
		}
	}
}

void
roa_finish(struct signed_object *so)
{
	cer_finish_ee(&so->ee, so->meta);
	finish_addrs(so);
	content_info_finish(so, &asn_DEF_RouteOriginAttestation);
}

void
roa_write(struct signed_object *so)
{
	asn1_write(so->meta->path, &asn_DEF_ContentInfo, &so->ci);
}
