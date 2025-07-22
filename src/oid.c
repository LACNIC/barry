#include "oid.h"

#include <openssl/objects.h>
#include "print.h"

int NID_ip_v2;			/* RFC 8360 */
int NID_asn_v2;			/* RFC 8360 */
int NID_resource_policy_v1;	/* RFC 6484 */
int NID_resource_policy_v2;	/* RFC 8360 */

static int
register_oid(const char *oid, const char *sn, const char *ln)
{
	int nid;

	nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		/* Note: Implicit object registration happens in OBJ_create. */
		nid = OBJ_create(oid, sn, ln);
		if (nid == 0)
			panic("Unable to register the %s NID.", sn);
	}

	return nid;
}

void
oid_setup(void)
{
	/* Old: NID_sbgp_ipAddrBlock */
	NID_ip_v2 = register_oid("1.3.6.1.5.5.7.1.28",
	    "ip2", "ipAddrBlocks-v2");

	/* Old: NID_sbgp_autonomousSysNum */
	NID_asn_v2 = register_oid("1.3.6.1.5.5.7.1.29",
	    "asn2", "autonomousSysIds-v2");

	NID_resource_policy_v1 = register_oid("1.3.6.1.5.5.7.14.2",
	    "ip-asn", "ipAddr-asNumber");

	NID_resource_policy_v2 = register_oid("1.3.6.1.5.5.7.14.3",
	    "ip-asn-v2", "ipAddr-asNumber-v2");
}

char const *
oid2str(char const *txt)
{
	ASN1_OBJECT *obj;
	int nid;

	obj = OBJ_txt2obj(txt, 1);
	if (!obj)
		return NULL;

	nid = OBJ_obj2nid(obj);
	if (nid == NID_undef)
		return NULL;

	return OBJ_nid2ln(nid);
}
