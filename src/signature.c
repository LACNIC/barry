#include "signature.h"

#include <libasn1fort/der_encoder.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "print.h"

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
