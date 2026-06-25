#ifndef SRC_OID_H_
#define SRC_OID_H_

#include <libasn1fort/OBJECT_IDENTIFIER.h>
#include <stdbool.h>

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

bool is_oid(OBJECT_IDENTIFIER_t *oid, const int ref[]);
bool oid_is_caIssuers(OBJECT_IDENTIFIER_t *);
bool oid_is_caRepository(OBJECT_IDENTIFIER_t *);
bool oid_is_rpkiManifest(OBJECT_IDENTIFIER_t *);
bool oid_is_rpkiNotify(OBJECT_IDENTIFIER_t *);
bool oid_is_signedObject(OBJECT_IDENTIFIER_t *);

char const *oid2str(char const *);

#endif /* SRC_OID_H_ */
