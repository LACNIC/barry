#ifndef SRC_ROA_H_
#define SRC_ROA_H_

#include <libasn1fort/RouteOriginAttestation.h>
#include "cer.h"
#include "keyval.h"
#include "so.h"

struct signed_object *roa_new(char const *, struct rpki_certificate *);
void roa_generate_paths(struct signed_object *, char const *);
void roa_apply_keyvals(struct signed_object *, struct keyvals *);
void roa_finish(struct signed_object *);
void roa_write(struct signed_object *);
void roa_print(struct signed_object *);

#endif /* SRC_ROA_H_ */
