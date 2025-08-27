#ifndef SRC_SIGNATURE_H_
#define SRC_SIGNATURE_H_

#include <libasn1fort/SignatureValue.h>
#include <openssl/evp.h>
#include <stdbool.h>

SignatureValue_t do_sign(void *, const struct asn_TYPE_descriptor_s *,
    EVP_PKEY *, bool);

#endif /* SRC_SIGNATURE_H_ */
