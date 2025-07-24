#include "oid.h"

#include <openssl/objects.h>

/* Returns the libcrypto long name of the numeric representation @txt. */
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
