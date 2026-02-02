#include "asa.h"

#include <openssl/objects.h>
#include <libasn1fort/ASId.h>
#include <libasn1fort/ASProviderAttestation.h>

#include "asn1.h"
#include "print.h"

static int
aspa_nid(void)
{
	static char const *OID = "1.2.840.113549.1.9.16.1.49";
	static int nid = NID_undef;

	if (nid != NID_undef)
		return nid;

	nid = OBJ_txt2nid(OID);
	if (nid != NID_undef)
		return nid;

	nid = OBJ_create(OID, "ASPA", "RPKI ASPA (Content type)");
	if (nid != NID_undef)
		return nid;

	panic("Unable to register the ASPA NID.");
}

struct signed_object *
asa_new(struct rpki_tree_node *node)
{
	struct signed_object *so;
	ASProviderAttestation_t *aspa;
	struct field *eContent;

	so = signed_object_new(node, aspa_nid(), &eContent);
	aspa = eContent->address2 = &so->obj.aspa;

	aspa->version = intmax2INTEGER(1);
	field_add(eContent, "version", &ft_int, &aspa->version, sizeof(INTEGER_t));

	init_INTEGER(&aspa->customerASID, 0);
	field_add(eContent, "customerASID", &ft_int, &aspa->customerASID, 0);

	INIT_ASN1_ARRAY(&aspa->providers.list, 1, ASId_t);
	field_add(eContent, "providers", &ft_providers, &aspa->providers, 0);

	return so;
}

static ASId_t
find_first_asnum(struct ASIdentifierChoice__asIdsOrRanges *aiors)
{
	static ASId_t zero = { 0 };
	ASIdOrRange_t *aior;

	if (aiors->list.count == 0)
		return zero;

	aior = aiors->list.array[0];
	switch (aior->present) {
	case ASIdOrRange_PR_id:
		return aior->choice.id;
	case ASIdOrRange_PR_range:
		return aior->choice.range.min;
	case ASIdOrRange_PR_NOTHING:
		break;
	}

	return zero;
}

static struct ASIdentifierChoice__asIdsOrRanges *
find_resources(struct rpki_tree_node *node)
{
	struct rpki_certificate *cer;
	struct ext_list_node *ext;

	for (; node != NULL; node = node->parent) {
		cer = meta_certificate(&node->meta);
		if (!cer)
			return NULL;

		ext = cer_ext(cer, EXT_ASN);
		if (!ext)
			return NULL;

		switch (ext->v.asn.asnum->present) {
		case ASIdentifierChoice_PR_asIdsOrRanges:
			return &ext->v.asn.asnum->choice.asIdsOrRanges;
		case ASIdentifierChoice_PR_inherit:
			break;
		case ASIdentifierChoice_PR_NOTHING:
			return NULL;
		}
	}

	return NULL;
}

static void
finish_customerASID(struct signed_object *so)
{
	struct ext_list_node *ext;
	struct ASIdentifierChoice__asIdsOrRanges *aiors;

	if (fields_overridden(so->objf,
	    "content.encapContentInfo.eContent.customerASID"))
		return;

	ext = cer_ext(&so->ee, EXT_ASN);
	if (!ext)
		return;

	aiors = find_resources(so->meta->node);
	if (!aiors)
		return;

	so->obj.aspa.customerASID = find_first_asnum(aiors);
}

void
asa_finish(struct signed_object *so)
{
	if (fields_overridden(so->objf, "content"))
		return;

	cer_finish_ee(&so->ee, so->meta);
	finish_customerASID(so);
	content_info_finish(so, &asn_DEF_ASProviderAttestation);
}

void
asa_write(struct signed_object *so)
{
	asn1_write(so->meta->path, &asn_DEF_ContentInfo, &so->ci);
}
