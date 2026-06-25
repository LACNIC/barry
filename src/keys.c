#include "keys.h"

#include <errno.h>
#include <libasn1fort/BIT_STRING.h>
#include <libasn1fort/OCTET_STRING.h>
#include <libasn1fort/SubjectPublicKeyInfo.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/rsa.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include "alloc.h"
#include "asn1.h"
#include "print.h"
#include "sha.h"
#include "str.h"

struct keys_array {
	EVP_PKEY **array;
	size_t count;
	size_t capacity;
};

extern char const *keys_path;

static struct keys_array keys;

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

static void
load_provided_keys(void)
{
	DIR *dir;
	struct dirent *f;
	int error;

	if (keys.count != 0)
		return;

	keys.capacity = 32;
	keys.array = pmalloc(keys.capacity * sizeof(EVP_PKEY *));
	keys.count = 0;

	dir = opendir(keys_path);
	if (!dir)
		panic("Cannot access %s: %s", keys_path, strerror(errno));

	for (errno = 0, f = readdir(dir); f; errno = 0, f = readdir(dir)) {
		if (f->d_name[0] == '.')
			continue;
		if (!str_has_suffix(f->d_name, ".pem"))
			continue;

		if (keys.count >= keys.capacity) {
			keys.capacity <<= 1;
			keys.array = prealloc(keys.array, keys.capacity * sizeof(EVP_PKEY *));
		}

		keys.array[keys.count] = load_evp_pkey(f->d_name);
		keys.count++;
	}
	error = errno;
	closedir(dir);

	if (error)
		panic("Bad %s traversal: %s", keys_path, strerror(error));
	if (keys.count == 0)
		panic("There are no .pem fies in %s.", keys_path);
}

void
keys_init(void)
{
	if (keys_path != NULL)
		load_provided_keys();
}

/* Not thread safe */
EVP_PKEY *
keys_new(char const *filename)
{
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

	hash_sha1((uint8_t *)filename, strlen(filename), &hash);
	if (hash.size != 20)
		panic("SHA1 size %zu != 20", hash.size);
	if (hash.size < sizeof(index))
		panic("Weird integer size: %zu", sizeof(index));
	memcpy(&index, hash.buf, sizeof(index));
	free(hash.buf);

	return keys.array[index % keys.count];
}

static bool
BIT_STRING_equals(BIT_STRING_t *a, BIT_STRING_t *b)
{
	if (a->size != b->size)
		return false;
	if (a->bits_unused != b->bits_unused)
		return false;
	return memcmp(a->buf, b->buf, a->size) == 0;
}

EVP_PKEY *
keys_find(char const *filename, SubjectPublicKeyInfo_t *spki)
{
	SubjectPublicKeyInfo_t kspki = { 0 };
	size_t i;

	for (i = 0; i < keys.count; i++) {
		pubkey2asn1(keys.array[i], &kspki);
		if (BIT_STRING_equals(&spki->subjectPublicKey, &kspki.subjectPublicKey))
			return keys.array[i];
		ASN_STRUCT_RESET(asn_DEF_SubjectPublicKeyInfo, &kspki);
	}

	pr_warn("%s: Unidentified keys. I will not be able to sign this certificate's children.",
	    filename);
	/* This is fine if children have overridden signatures, so keep going */
	return NULL;
}

/* *der should be freed with OPENSSL_free(). */
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

	OSSL_ENCODER_CTX_free(ctx);
}

void
pubkey2asn1(EVP_PKEY *pubkey, SubjectPublicKeyInfo_t *asn1)
{
	unsigned char *der;
	size_t derlen;

	pubkey2der(pubkey, &der, &derlen);
	ber2asn1(der, derlen, &asn_DEF_SubjectPublicKeyInfo, asn1);

	OPENSSL_free(der);
}
