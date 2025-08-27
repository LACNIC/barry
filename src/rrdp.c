#include "rrdp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file.h"
#include "libcrypto.h"

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
