#include "libcrypto.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/rsa.h>

#include "asn1.h"
#include "print.h"

/*
 * Base64-encodes the content of file @path,
 * writes result into file descriptor @fd.
 */
void
base64_into_fd(char const *path, int fdout)
{
	int fdin;
	EVP_ENCODE_CTX *ctx;
	unsigned char bufin[48];
	unsigned char bufout[66];
	ssize_t inl;
	int outl;

	fdin = open(path, O_RDONLY, 0);
	if (fdin < 0)
		panic("open(%s): %s", path, strerror(errno));

	ctx = EVP_ENCODE_CTX_new();
	if (!ctx)
		enomem;

	EVP_EncodeInit(ctx);

	do {
		inl = read(fdin, bufin, 48);
		if (inl < 0)
			panic("read()");
		if (inl == 0)
			break;
		if (!EVP_EncodeUpdate(ctx, bufout, &outl, bufin, inl))
			panic("EVP_EncodeUpdate()");
		if (write(fdout, bufout, outl) < 0)
			panic("write(1)");
	} while (1);

	EVP_EncodeFinal(ctx, bufout, &outl);
	if (write(fdout, bufout, outl) < 0)
		panic("write(2)");

	close(fdin);
}

void
pubkey2der(EVP_PKEY *keys, unsigned char **der, size_t *size)
{
	OSSL_ENCODER_CTX *ctx;

	*der = NULL;
	*size = 0;

	ctx = OSSL_ENCODER_CTX_new_for_pkey(keys, EVP_PKEY_PUBLIC_KEY,
	    "DER", "SubjectPublicKeyInfo", NULL);
	if (!ctx)
		panic("OSSL_ENCODER_CTX_new_for_pkey");
	if (1 != OSSL_ENCODER_to_data(ctx, der, size))
		panic("OSSL_ENCODER_to_data");
}

void
pubkey2asn1(EVP_PKEY *pubkey, SubjectPublicKeyInfo_t *asn1)
{
	unsigned char *der;
	size_t derlen;

	pubkey2der(pubkey, &der, &derlen);
	ber2asn1(der, derlen, &asn_DEF_SubjectPublicKeyInfo, asn1);
}

static char *
next_key(void)
{
	extern char const *keys_path;
	static unsigned int k;

	char *path;
	size_t pathlen;

	pathlen = strlen(keys_path) + 16;
	path = pzalloc(pathlen);
	psnprintf(path, pathlen, "%s/%u.pem", keys_path, k++);

	return path;
}

EVP_PKEY *
keys_new(void)
{
	extern char const *keys_path;

	char *path;
	FILE *file;
	OSSL_DECODER_CTX *ctx;
	EVP_PKEY *result;

	if (keys_path == NULL) {
		pr_debug("- Generating keypair from scratch.");
		result = EVP_RSA_gen(2048);
		if (!result)
			enomem; /* TODO May not be an ENOMEM */
		return result;
	}

	path = next_key();
	pr_debug("- Loading keypair: %s", path);

	file = fopen(path, "r");
	if (!file)
		panic("Cannot open %s: %s", path, strerror(errno));

	result = NULL;
	ctx = OSSL_DECODER_CTX_new_for_pkey(&result, "PEM", NULL, "RSA",
	    OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
	if (ctx == NULL)
		panic("OSSL_DECODER_CTX_new_for_pkey(priv): NULL");
	if (!OSSL_DECODER_from_fp(ctx, file))
		panic("OSSL_DECODER_from_data(priv): no");

	fclose(file);
	free(path);
	return result;
}

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

/* binary to char */
static char
hash_b2c(unsigned char bin)
{
	bin &= 0xF;
	return (bin < 10) ? (bin + '0') : (bin + 'a' - 10);
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

struct signing_args {
	EVP_MD_CTX *ctx;
	bool replace_0x31; /* Pretend the first input byte is 0x31? */
};

static void digest_sign_update(struct signing_args *args,
    const void *buffer, size_t size)
{
	if (1 != EVP_DigestSignUpdate(args->ctx, buffer, size))
		panic("EVP_DigestSignUpdate");
}

static int
der2sign(const void *der, size_t size, void *_args)
{
	static unsigned char const x31 = 0x31;
	struct signing_args *args = _args;

	if (size == 0)
		return 0;

	if (args->replace_0x31) {
		digest_sign_update(args, &x31, 1);
		digest_sign_update(args, ((unsigned char *)der) + 1, size - 1);
		args->replace_0x31 = false;
	} else {
		digest_sign_update(args, der, size);
	}

	return 0;
}

SignatureValue_t
do_sign(void *obj, const struct asn_TYPE_descriptor_s *td, EVP_PKEY *keys,
    bool replace_0x31)
{
	struct signing_args args;
	asn_enc_rval_t encode_result;
	unsigned char *sig;
	size_t siglen;
	SignatureValue_t result;

	args.ctx = EVP_MD_CTX_create();
	if (!args.ctx)
		panic("EVP_MD_CTX_create");
	args.replace_0x31 = replace_0x31;

	if (1 != EVP_DigestSignInit(args.ctx, NULL, EVP_sha256(), NULL, keys))
		panic("EVP_DigestSignInit");

	encode_result = der_encode(td, obj, der2sign, &args);
	if (encode_result.encoded < 0)
		panic("der_encode(): %zd", encode_result.encoded);

	if (1 != EVP_DigestSignFinal(args.ctx, NULL, &siglen))
		panic("EVP_DigestSignFinal 1");
	sig = OPENSSL_malloc(sizeof(unsigned char) * siglen);
	if (!sig)
		panic("sig OOM");
	if (1 != EVP_DigestSignFinal(args.ctx, sig, &siglen))
		panic("EVP_DigestSignFinal 2");

	result.buf = (uint8_t *)sig;
	result.size = siglen;
	return result;
}
