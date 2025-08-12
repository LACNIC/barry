#ifndef SRC_LIBCRYPTO_H_
#define SRC_UTIL_LIBCRYPTO_H_

#include <stdbool.h>
#include <openssl/evp.h>

#include <libasn1fort/SubjectPublicKeyInfo.h>
#include <libasn1fort/SignatureValue.h>

void base64_into_fd(char const *, int);

void pubkey2der(EVP_PKEY *, unsigned char **, size_t *);
void pubkey2asn1(EVP_PKEY *pubkey, SubjectPublicKeyInfo_t *asn1);

EVP_PKEY *keys_new(void);

void hash_sha1(uint8_t *, size_t, OCTET_STRING_t *);
void hash_sha256(uint8_t *, size_t, OCTET_STRING_t *);

void sha256_file(char const *, unsigned char *, unsigned int *);
char *sha256_file_str(char const *);

SignatureValue_t do_sign(void *, const struct asn_TYPE_descriptor_s *,
    EVP_PKEY *, bool);

#endif /* SRC_LIBCRYPTO_H_ */
