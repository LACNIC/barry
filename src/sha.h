#ifndef SRC_SHA_H_
#define SRC_SHA_H_

#include <libasn1fort/OCTET_STRING.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

void hash_sha1(uint8_t *, size_t, OCTET_STRING_t *);
void hash_sha256(uint8_t *, size_t, OCTET_STRING_t *);
void sha256_file(char const *, unsigned char *, unsigned int *);
char *sha256_file_str(char const *);

#endif /* SRC_SHA_H_ */
