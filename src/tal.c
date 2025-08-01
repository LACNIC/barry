#include "tal.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "libcrypto.h"
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
	int fd;
	unsigned char *der;
	size_t size;
	int error;

	pr_debug("Writing TAL: %s", path);

	if (unlink(path)) {
		error = errno;
		if (error != ENOENT)
			panic("Cannot remove old file: %s", strerror(error));
	}

	fd = open(path, O_WRONLY | O_CREAT, 0640);
	if (fd < 0)
		panic("open(%s): %s", path, strerror(errno));

	if (write(fd, ta->uri, strlen(ta->uri)) < 0)
		panic("write(1)");
	if (write(fd, "\n\n", strlen("\n\n")) < 0)
		panic("write(2)");

	pubkey2der(ta->keys, &der, &size);
	base64_pubkey(der, size, fd);

	close(fd);
}
