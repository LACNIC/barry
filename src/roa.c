#include "roa.h"

#include "asn1.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"

struct signed_object *
roa_new(struct rpki_object *meta)
{
	static const uint8_t IPV4[2] = { 0, 1 };
	/* static const uint8_t IPV6[2] = { 0, 2 }; */
	static const uint8_t ADDR[3] = { 192, 0, 2 };

	struct signed_object *so;
	RouteOriginAttestation_t *roa;
	struct field *eContent;
	struct ROAIPAddressFamily *riaf;
	ROAIPAddress_t *ria;

	so = signed_object_new(meta, NID_id_ct_routeOriginAuthz, &eContent);
	roa = &so->obj.roa;

	roa->version = intmax2INTEGER(0);
	field_add(eContent, "version", &ft_int, &roa->version, sizeof(INTEGER_t));

	init_INTEGER(&roa->asId, 1234);
	field_add(eContent, "asId", &ft_int, &roa->asId, 0);

	INIT_ASN1_ARRAY(&roa->ipAddrBlocks.list, 1, ROAIPAddressFamily_t);
	field_add(eContent, "ipAddrBlocks", &ft_ip_roa, &roa->ipAddrBlocks, 0);

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
roa_generate_paths(struct signed_object *so)
{
	/* Empty */
}

void
roa_finish(struct signed_object *so)
{
	signed_object_finish(so, &asn_DEF_RouteOriginAttestation);
}

void
roa_write(struct signed_object *so)
{
	asn1_write(so->meta->path, &asn_DEF_ContentInfo, &so->ci);
}

void
roa_print_md(struct signed_object *so)
{
	printf("- Type: ROA\n");
}

void
roa_print_csv(struct signed_object *so)
{
	so_print_csv(so);
}
