#ifndef SRC_SIGNATURE_H_
#define SRC_SIGNATURE_H_

#include <libasn1fort/SignatureValue.h>
#include <stdbool.h>
#include "cer.h"

SignatureValue_t do_sign(void *, const struct asn_TYPE_descriptor_s *,
    struct rpki_certificate *, bool);

#endif /* SRC_SIGNATURE_H_ */
