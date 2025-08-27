#include "sha.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "print.h"

static void
do_hash(char const *algorithm, uint8_t *buf, size_t buflen, OCTET_STRING_t *hash)
{
	EVP_MD *md;
	EVP_MD_CTX *ctx;
	unsigned char actual[EVP_MAX_MD_SIZE];
	unsigned int actual_len;

	md = EVP_MD_fetch(NULL, algorithm, NULL);
	if (md == NULL)
		panic("EVP_MD_fetch");

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		enomem;

	if (!EVP_DigestInit_ex(ctx, md, NULL) ||
	    !EVP_DigestUpdate(ctx, buf, buflen) ||
	    !EVP_DigestFinal_ex(ctx, actual, &actual_len))
		panic("Buffer hashing failed");

	EVP_MD_CTX_free(ctx);

	hash->size = actual_len;
	hash->buf = pmalloc(hash->size);
	memcpy(hash->buf, actual, hash->size);
}

void
hash_sha1(uint8_t *buf, size_t buflen, OCTET_STRING_t *hash)
{
	do_hash("SHA1", buf, buflen, hash);
}

void
hash_sha256(uint8_t *buf, size_t buflen, OCTET_STRING_t *hash)
{
	do_hash("SHA256", buf, buflen, hash);
}

static void
__sha256_file(char const *path, EVP_MD_CTX *ctx)
{
	int fdin;
	unsigned char bufin[1024];
	ssize_t inl;

	fdin = open(path, O_RDONLY, 0);
	if (fdin < 0)
		panic("open(%s): %s", path, strerror(errno));

	do {
		inl = read(fdin, bufin, 1024);
		if (inl < 0)
			panic("read()");
		if (inl == 0)
			break;
		if (!EVP_DigestUpdate(ctx, bufin, inl))
			panic("EVP_DigestUpdate");
	} while (1);

	close(fdin);
}

/* @result has to length @EVP_MAX_MD_SIZE. */
void
sha256_file(char const *path, unsigned char *result, unsigned int *rlen)
{
	EVP_MD *md;
	EVP_MD_CTX *ctx;

	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (md == NULL)
		panic("EVP_MD_fetch");

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		enomem;

	if (!EVP_DigestInit_ex(ctx, md, NULL))
		panic("EVP_DigestInit_ex");
	__sha256_file(path, ctx);
	if (!EVP_DigestFinal_ex(ctx, result, rlen))
		panic("EVP_DigestFinal_ex");

	EVP_MD_CTX_free(ctx);
}

/* binary to char */
static char
hash_b2c(unsigned char bin)
{
	bin &= 0xF;
	return (bin < 10) ? (bin + '0') : (bin + 'a' - 10);
}

char *
sha256_file_str(char const *path)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len;
	char *result;
	size_t i;

	sha256_file(path, md, &len);

	result = pmalloc(2 * len + 1);
	for (i = 0; i < len; i++) {
		result[2 * i + 0] = hash_b2c(md[i] >> 4);
		result[2 * i + 1] = hash_b2c(md[i]);
	}
	result[2 * i] = '\0';
	return result;
}
