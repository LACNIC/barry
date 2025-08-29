#include "tal.h"

#include "alloc.h"
#include "file.h"
#include "keys.h"
#include "print.h"

char *
tal_autogenerate_path(char const *rd)
{
	char const *slash;
	char const *dot;
	size_t rdlen;
	char *result;

	if (rd == NULL || strcmp(rd, "-") == 0)
		return "repo.tal";

	slash = strrchr(rd, '/');
	if (slash == NULL)
		slash = rd;
	dot = strrchr(slash + 1, '.');
	rdlen = (dot == NULL) ? strlen(rd) : dot - rd;

	result = pmalloc(rdlen + 4);
	strncpy(result, rd, rdlen);
	strcpy(result + rdlen, ".tal");
	return result;
}

static void
base64_pubkey(unsigned char *in, int inl, int fd)
{
	EVP_ENCODE_CTX *ctx;
	unsigned char *limit;
	unsigned char out[66];
	int outl;

	ctx = EVP_ENCODE_CTX_new();
	if (!ctx)
		enomem;

	EVP_EncodeInit(ctx);

	for (limit = in + inl; in < limit; in += 48) {
		inl = limit - in;
		inl = (48 < inl) ? 48 : inl;
		if (!EVP_EncodeUpdate(ctx, out, &outl, in, inl))
			panic("EVP_EncodeUpdate()");
		if (write(fd, out, outl) < 0)
			panic("write(1)");
	}

	EVP_EncodeFinal(ctx, out, &outl);
	if (write(fd, out, outl) < 0)
		panic("write(2)");
}

void
tal_write(struct rpki_certificate *ta, char const *path)
{
	extern char const *rrdp_uri;

	int fd;
	char *uri;
	unsigned char *der;
	size_t size;

	pr_debug("Writing TAL: %s", path);

	fd = write_open(path);

	if (rrdp_uri) {
		uri = join_paths(rrdp_uri, ta->meta->name);
		if (write(fd, uri, strlen(uri)) < 0)
			panic("write(HTTP URI)");
		free(uri);
		if (write(fd, "\n", 1) < 0)
			panic("write(nl)");
	}
	if (write(fd, ta->meta->uri, strlen(ta->meta->uri)) < 0)
		panic("write(rsync URI)");
	if (write(fd, "\n\n", strlen("\n\n")) < 0)
		panic("write(nlnl)");

	pubkey2der(ta->keys, &der, &size);
	base64_pubkey(der, size, fd);

	close(fd);
}
