#ifndef SRC_ROA_H_
#define SRC_ROA_H_

#include <libasn1fort/RouteOriginAttestation.h>
#include "cer.h"
#include "keyval.h"
#include "so.h"

struct signed_object *roa_new(struct rpki_object *);
void roa_generate_paths(struct signed_object *);
void roa_finish(struct signed_object *);
void roa_write(struct signed_object *);
void roa_print(struct signed_object *);

#endif /* SRC_ROA_H_ */
