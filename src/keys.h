#ifndef SRC_KEYS_H_
#define SRC_KEYS_H_

#include <openssl/evp.h>
#include <stddef.h>

EVP_PKEY *keys_new(void);
void pubkey2der(EVP_PKEY *, unsigned char **, size_t *);

#endif /* SRC_KEYS_H_ */
