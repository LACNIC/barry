#include "oid.h"

#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <stddef.h>

const int OID_CA_ISSUERS[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0 };
const int OID_CA_REPOSITORY[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, 0 };
const int OID_RPKI_MANIFEST[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0A, 0 };
const int OID_RPKI_NOTIFY[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0D, 0 };
const int OID_SIGNED_OBJECT[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0B, 0 };

static bool
is_oid(OBJECT_IDENTIFIER_t *oid, const int ref[])
{
	size_t i;

	for (i = 0; i < oid->size; i++)
		if (oid->buf[i] != ref[i])
			return false;

	return ref[i] == 0;
}

bool
oid_is_caIssuers(OBJECT_IDENTIFIER_t *oid)
{
	return is_oid(oid, OID_CA_ISSUERS);
}

bool
oid_is_caRepository(OBJECT_IDENTIFIER_t *oid)
{
	return is_oid(oid, OID_CA_REPOSITORY);
}

bool
oid_is_rpkiManifest(OBJECT_IDENTIFIER_t *oid)
{
	return is_oid(oid, OID_RPKI_MANIFEST);
}

bool
oid_is_rpkiNotify(OBJECT_IDENTIFIER_t *oid)
{
	return is_oid(oid, OID_RPKI_NOTIFY);
}

bool
oid_is_signedObject(OBJECT_IDENTIFIER_t *oid)
{
	return is_oid(oid, OID_SIGNED_OBJECT);
}

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
