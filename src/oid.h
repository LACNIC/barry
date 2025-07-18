#ifndef SRC_OID_H_
#define SRC_OID_H_

#include <stdbool.h>
#include <libasn1fort/OBJECT_IDENTIFIER.h>

extern const int OID_COMMON_NAME[];
extern const int OID_SHA256[];
extern const int OID_RSA_ENCRYPTION[];
extern const int OID_SHA256_WITH_RSA_ENCRYPTION[];

extern const int OID_SIGNED_DATA[];
extern const int OID_RPKI_MANIFEST[];
extern const int OID_RPKI_ROA[];
extern const int OID_CONTENT_TYPE[];
extern const int OID_MSG_DIGEST[];
extern const int OID_MSG_SIGNING_TIME[];

extern const int OID_BC[];
extern const int OID_SKI[];
extern const int OID_AKI[];
extern const int OID_KU[];
extern const int OID_CRLDP[];
extern const int OID_AIA[];
extern const int OID_SIA[];
extern const int OID_CP[];
extern const int OID_IP[];
extern const int OID_ASN[];
extern const int OID_CRLN[];

extern const int OID_CA_ISSUERS[];
extern const int OID_CA_REPOSITORY[];
extern const int OID_SIA_RPKI_MANIFEST[];
extern const int OID_RPKI_NOTIFY[];
extern const int OID_SIGNED_OBJECT[];

extern const int OID_RESOURCE_POLICY[];

char const *oid2str(OBJECT_IDENTIFIER_t *oid);

#endif /* SRC_OID_H_ */
