#include "keys.h"

#include <errno.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/rsa.h>
#include <string.h>

#include "alloc.h"
#include "print.h"

extern char const *keys_path;

static char *
get_key_path(unsigned int k)
{
	char *path;
	size_t pathlen;

	pathlen = strlen(keys_path) + 16;
	path = pzalloc(pathlen);
	psnprintf(path, pathlen, "%s/%u.pem", keys_path, k);

	return path;
}

EVP_PKEY *
keys_new(void)
{
	static unsigned int k;

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

retry:	path = get_key_path(k);
	pr_debug("- Loading keypair: %s", path);

	file = fopen(path, "r");
	if (!file) {
		if (k == 0)
			panic("Cannot open %s: %s", path, strerror(errno));
		else
			pr_debug("Cannot open %s: %s", path, strerror(errno));
		k = 0;
		goto retry;
	}
	k++;

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
