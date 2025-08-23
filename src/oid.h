#ifndef SRC_OID_H_
#define SRC_OID_H_

#include <stdbool.h>
#include <libasn1fort/OBJECT_IDENTIFIER.h>

bool oid_is_caIssuers(OBJECT_IDENTIFIER_t *);
bool oid_is_caRepository(OBJECT_IDENTIFIER_t *);
bool oid_is_rpkiManifest(OBJECT_IDENTIFIER_t *);
bool oid_is_rpkiNotify(OBJECT_IDENTIFIER_t *);
bool oid_is_signedObject(OBJECT_IDENTIFIER_t *);

char const *oid2str(char const *);

#endif /* SRC_OID_H_ */
