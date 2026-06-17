#include "keys.h"

#include <errno.h>
#include <libasn1fort/OCTET_STRING.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/rsa.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include "alloc.h"
#include "print.h"
#include "sha.h"
#include "str.h"

struct keys_array {
	EVP_PKEY **array;
	size_t count;
	size_t capacity;
};

extern char const *keys_path;

static EVP_PKEY *
load_evp_pkey(char const *basename)
{
	char *path;
	FILE *file;
	OSSL_DECODER_CTX *ctx;
	EVP_PKEY *result;

	path = path_join(keys_path, basename);
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

static struct keys_array
load_provided_keys(void)
{
	DIR *dir;
	struct dirent *f;
	struct keys_array res;
	int error;

	res.capacity = 32;
	res.array = pmalloc(res.capacity * sizeof(EVP_PKEY *));
	res.count = 0;

	dir = opendir(keys_path);
	if (!dir)
		panic("Cannot access %s: %s", keys_path, strerror(errno));

	for (errno = 0, f = readdir(dir); f; errno = 0, f = readdir(dir)) {
		if (f->d_name[0] == '.')
			continue;
		if (!str_has_suffix(f->d_name, ".pem"))
			continue;

		if (res.count >= res.capacity) {
			res.capacity <<= 1;
			res.array = prealloc(res.array, res.capacity * sizeof(EVP_PKEY *));
		}

		res.array[res.count] = load_evp_pkey(f->d_name);
		res.count++;
	}
	error = errno;
	closedir(dir);

	if (error)
		panic("Bad %s traversal: %s", keys_path, strerror(error));
	if (res.count == 0)
		panic("There are no .pem fies in %s.", keys_path);

	return res;
}

/* Not thread safe */
EVP_PKEY *
keys_new(char const *filename)
{
	static struct keys_array keys;

	OCTET_STRING_t hash = { 0 };
	unsigned int index;
	EVP_PKEY *result;

	if (keys_path == NULL) {
		pr_debug("- Generating keypair from scratch.");
		result = EVP_RSA_gen(2048);
		if (!result)
			enomem; /* TODO May not be an ENOMEM */
		return result;
	}

	if (keys.count == 0) /* Uninitialized? */
		keys = load_provided_keys();

	hash_sha1((uint8_t *)filename, strlen(filename), &hash);
	if (hash.size != 20)
		panic("SHA1 size %zu != 20", hash.size);
	if (hash.size < sizeof(index))
		panic("Weird integer size: %zu", sizeof(index));
	memcpy(&index, hash.buf, sizeof(index));
	free(hash.buf);

	return keys.array[index % keys.count];
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
