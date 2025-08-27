#include "rrdp.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file.h"
#include "print.h"

struct rrdp_type {
	char const *name;
};

const struct rrdp_type SNAPSHOT = { "snapshot" };
const struct rrdp_type DELTA = { "delta" };

struct rrdp_entry_type {
	char const *name;
};

const struct rrdp_entry_type PUBLISH = { "publish" };
const struct rrdp_entry_type WITHDRAW = { "withdraw" };

void
rrdp_save_notification(char const *path, char const *ss_uri, char const *ss_hash)
{
	int fd;

	fd = write_open(path);

	// TODO the attributes need to be args
	dprintf(fd, "<notification xmlns=\"%s\"\n", "http://www.ripe.net/rpki/rrdp");
	dprintf(fd, "              version=\"%u\"\n", 1);
	dprintf(fd, "              session_id=\"%s\"\n", "9df4b597-af9e-4dca-bdda-719cce2c4e28");
	dprintf(fd, "              serial=\"%u\">\n", 3);
	dprintf(fd, "  <snapshot uri=\"%s\" hash=\"%s\"/>\n", ss_uri, ss_hash);
	dprintf(fd, "</notification>\n");

	close(fd);
}

/*
 * Base64-encodes the content of file @path,
 * writes result into file descriptor @fd.
 */
static void
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
rrdp_save_snapshot(char const *path, struct rrdp_type const *type,
    struct rrdp_entry_file *files, unsigned int count)
{
	extern char const *rsync_path;

	int fd;
	unsigned int tabbing;
	unsigned int f;
	struct rrdp_entry_file *file;
	char *file_path;

	fd = write_open(path);

	tabbing = strlen(type->name) + 2;
	dprintf(fd, "<%s xmlns=\"%s\"\n", type->name, "http://www.ripe.net/rpki/rrdp");
	dprintf(fd, "%*cversion=\"%u\"\n", tabbing, ' ', 1);
	dprintf(fd, "%*csession_id=\"%s\"\n", tabbing, ' ', "9df4b597-af9e-4dca-bdda-719cce2c4e28");
	dprintf(fd, "%*cserial=\"%u\">\n", tabbing, ' ', 3);

	for (f = 0; f < count; f++) {
		file = &files[f];

		tabbing = strlen(file->type->name) + 4;
		dprintf(fd, "  <%s uri=\"%s\"", file->type->name, file->uri);
		if (file->hash)
			dprintf(fd, "\n%*chash=\"%s\"", tabbing, ' ', file->hash);
		dprintf(fd, ">\n");

		file_path = join_paths(rsync_path, file->path);
		base64_into_fd(file_path, fd);
		free(file_path);

		dprintf(fd, "  </%s>\n", file->type->name);
	}

	dprintf(fd, "</%s>\n", type->name);

	close(fd);
}
