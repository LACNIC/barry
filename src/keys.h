#ifndef SRC_KEYS_H_
#define SRC_KEYS_H_

#include <libasn1fort/SubjectPublicKeyInfo.h>
#include <openssl/evp.h>
#include <stddef.h>

void keys_init(void);

EVP_PKEY *keys_new(char const *);
EVP_PKEY *keys_find(char const *, SubjectPublicKeyInfo_t *);
void pubkey2der(EVP_PKEY *, unsigned char **, size_t *);
void pubkey2asn1(EVP_PKEY *, SubjectPublicKeyInfo_t *);

#endif /* SRC_KEYS_H_ */
