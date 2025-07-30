#include "roa.h"

#include "asn1.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"

static const struct field_template roa_metadata[] = {
	{
		"content.encapContentInfo.eContent.version",
		&ft_int,
		offsetof(struct signed_object, obj.roa.version),
		sizeof(INTEGER_t),
	}, {
		"content.encapContentInfo.eContent.asId",
		&ft_int,
		offsetof(struct signed_object, obj.roa.asId)
	}, {
		"content.encapContentInfo.eContent.ipAddrBlocks",
		&ft_ip_roa,
		offsetof(struct signed_object, obj.roa.ipAddrBlocks)
	},
	{ 0 }
};

struct signed_object *
roa_new(char const *filename, struct rpki_certificate *parent)
{
	static const uint8_t IPV4[2] = { 0, 1 };
	/* static const uint8_t IPV6[2] = { 0, 2 }; */
	static const uint8_t ADDR[3] = { 192, 0, 2 };

	struct signed_object *so;
	RouteOriginAttestation_t *roa;
	struct ROAIPAddressFamily *riaf;
	ROAIPAddress_t *ria;

	so = signed_object_new(filename, parent, NID_id_ct_routeOriginAuthz);
	fields_compile(roa_metadata, NULL, so, &so->fields);

	roa = &so->obj.roa;

	roa->version = intmax2INTEGER(0);
	init_INTEGER(&roa->asId, 1234);
	INIT_ASN1_ARRAY(&roa->ipAddrBlocks.list, 1, ROAIPAddressFamily_t);

	riaf = roa->ipAddrBlocks.list.array[0];
	riaf->addressFamily.buf = (uint8_t *)IPV4;
	riaf->addressFamily.size = sizeof(IPV4) / sizeof(IPV4[0]);
	INIT_ASN1_ARRAY(&riaf->addresses.list, 1, ROAIPAddress_t);

	ria = riaf->addresses.list.array[0];
	ria->address.buf = (uint8_t *)ADDR;
	ria->address.size = sizeof(ADDR) / sizeof(ADDR[0]);

	return so;
}

void
roa_generate_paths(struct signed_object *so, char const *filename)
{
	so->uri = generate_uri(so->parent, filename);
	pr_debug("- uri: %s", so->uri);

	so->path = generate_path(so->parent, filename);
	pr_debug("- path: %s", so->path);
}

void
roa_apply_keyvals(struct signed_object *so, struct keyvals *kvs)
{
	fields_apply_keyvals(so->fields, so, kvs);
}

void
roa_finish(struct signed_object *so)
{
	signed_object_finish(so, &asn_DEF_RouteOriginAttestation);
}

void
roa_write(struct signed_object *so)
{
	asn1_write(so->path, &asn_DEF_ContentInfo, &so->ci);
}

void
roa_print(struct signed_object *so)
{
	printf("- Type: ROA\n");
	printf("- URI : %s\n", so->uri);
	printf("- Path: %s\n", so->path);

	fields_print(so->fields);
}
