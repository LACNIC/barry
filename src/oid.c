#include "oid.h"

const int OID_COMMON_NAME[] = { 0x55, 0x04, 0x03, 0 };
const int OID_SHA256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0 };
const int OID_RSA_ENCRYPTION[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0 };
const int OID_SHA256_WITH_RSA_ENCRYPTION[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0 };

const int OID_SIGNED_DATA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0 };
const int OID_RPKI_MANIFEST[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x1A, 0 };
const int OID_RPKI_ROA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x18, 0 };
const int OID_CONTENT_TYPE[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0};
const int OID_MSG_DIGEST[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0};
const int OID_MSG_SIGNING_TIME[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05, 0};

const int OID_BC[] = { 0x55, 0x1D, 0x13, 0 };
const int OID_SKI[] = { 0x55, 0x1D, 0x0E, 0 };
const int OID_AKI[] = { 0x55, 0x1D, 0x23, 0 };
const int OID_KU[] = { 0x55, 0x1D, 0x0F, 0 };
const int OID_CRLDP[] = { 0x55, 0x1D, 0x1F, 0 };
const int OID_AIA[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0 };
const int OID_SIA[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B, 0 };
const int OID_CP[] = { 0x55, 0x1D, 0x20, 0 };
const int OID_IP[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07, 0 };
const int OID_ASN[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08, 0 };
const int OID_CRLN[] = { 0x55, 0x1D, 0x14, 0 };

const int OID_CA_ISSUERS[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0 };
const int OID_CA_REPOSITORY[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, 0 };
const int OID_SIA_RPKI_MANIFEST[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0A, 0 };
const int OID_RPKI_NOTIFY[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0D, 0 };
const int OID_SIGNED_OBJECT[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x0B, 0 };

const int OID_RESOURCE_POLICY[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0E, 0x02, 0 };

static bool
is_oid(OBJECT_IDENTIFIER_t *oid, const int ref[])
{
	size_t i;

	for (i = 0; i < oid->size; i++)
		if (oid->buf[i] != ref[i])
			return false;

	return ref[i] == 0;
}

char const *
oid2str(OBJECT_IDENTIFIER_t *oid)
{
	if (is_oid(oid, OID_COMMON_NAME))
		return "commonName";
	if (is_oid(oid, OID_SHA256))
		return "sha256";
	if (is_oid(oid, OID_RSA_ENCRYPTION))
		return "rsaEncryption";
	if (is_oid(oid, OID_SHA256_WITH_RSA_ENCRYPTION))
		return "sha256WithRSAEncryption";
	if (is_oid(oid, OID_SIGNED_DATA))
		return "signedData";
	if (is_oid(oid, OID_RPKI_MANIFEST))
		return "rpkiManifest";
	if (is_oid(oid, OID_RPKI_ROA))
		return "rpkiRoa";
	if (is_oid(oid, OID_CONTENT_TYPE))
		return "contentType";
	if (is_oid(oid, OID_MSG_DIGEST))
		return "msgDigest";
	if (is_oid(oid, OID_MSG_SIGNING_TIME))
		return "msgSigningTime";
	if (is_oid(oid, OID_BC))
		return "Basic Constraints";
	if (is_oid(oid, OID_SKI))
		return "Subject Key Identifier";
	if (is_oid(oid, OID_AKI))
		return "Authority Key Identifier";
	if (is_oid(oid, OID_KU))
		return "Key Usage";
	if (is_oid(oid, OID_CRLDP))
		return "CRL Distribution Points";
	if (is_oid(oid, OID_AIA))
		return "Authority Information Access";
	if (is_oid(oid, OID_SIA))
		return "Subject Information Access";
	if (is_oid(oid, OID_CP))
		return "Certificate Policies";
	if (is_oid(oid, OID_IP))
		return "I PResources";
	if (is_oid(oid, OID_ASN))
		return "ASN Resources";
	if (is_oid(oid, OID_CRLN))
		return "CRL Number";
	if (is_oid(oid, OID_CA_ISSUERS))
		return "CA Issuers";
	if (is_oid(oid, OID_CA_REPOSITORY))
		return "caRepository";
	if (is_oid(oid, OID_SIA_RPKI_MANIFEST))
		return "rpkiManifest";
	if (is_oid(oid, OID_RPKI_NOTIFY))
		return "rpkiNotify";
	if (is_oid(oid, OID_SIGNED_OBJECT))
		return "signedObject";
	if (is_oid(oid, OID_RESOURCE_POLICY))
		return "Certificate Policies";

	return NULL;
}
