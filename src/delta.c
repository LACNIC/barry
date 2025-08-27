#include "delta.h"

#include <errno.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <libasn1fort/GeneralizedTime.h>
#include <libasn1fort/Time.h>
#include <libxml/xmlreader.h>
#include <openssl/evp.h>

#include "alloc.h"
#include "file.h"
#include "libcrypto.h"
#include "print.h"
#include "uthash.h"

/* Mocks */

char const *rsync_path;
char const *keys_path;
Time_t default_now;
Time_t default_later;
GeneralizedTime_t default_gnow;
GeneralizedTime_t default_glater;
unsigned int verbosity;

/* Real code */

#define HASHSIZE 32

struct rrdp_meta {
	char *version;
	char *session_id;
	char *serial;
};

struct notification_snapshot {
	char *uri;
	char *hash;
};

struct notification_delta {
	char *serial;
	char *uri;
	char *hash;

	STAILQ_ENTRY(notification_delta) hook;
};

STAILQ_HEAD(notification_deltas, notification_delta);

struct notification {
	struct rrdp_meta meta;
	struct notification_snapshot snapshot;
	struct notification_deltas deltas;
};

struct publish {
	char *uri;
	unsigned char hash[HASHSIZE];
	UT_hash_handle hh;
};

struct snapshot {
	struct rrdp_meta meta;
	struct publish *publishings; /* Hash table */
};

enum delta_type {
	DT_PUBLISH,
	DT_MODIFY,
	DT_WITHDRAW,
};

struct delta {
	enum delta_type type;
	char const *uri;
	unsigned char hash[HASHSIZE];

	UT_hash_handle hh;
};

struct deltas {
	struct rrdp_meta *meta;
	struct delta *ht;
};


static void
print_sha256(int fd, unsigned char *sha)
{
	size_t i;
	for (i = 0; i < HASHSIZE; i++)
		dprintf(fd, "%x", sha[i]);
}

static char *
xmlChar2str(xmlTextReaderPtr reader, char const *name)
{
	xmlChar *xc;
	char *str;

	xc = xmlTextReaderGetAttribute(reader, BAD_CAST name);
	str = pstrdup((char *)xc);
	xmlFree(xc);

	return str;
}

static void
collect_meta(xmlTextReaderPtr reader, struct rrdp_meta *meta)
{
	meta->version = xmlChar2str(reader, "version");
	meta->session_id = xmlChar2str(reader, "session_id");
	meta->serial = xmlChar2str(reader, "serial");
}

static void
collect_notif_delta(xmlTextReaderPtr reader, struct notification_deltas *deltas)
{
	struct notification_delta *delta;

	delta = pzalloc(sizeof(struct notification_delta));
	delta->serial = xmlChar2str(reader, "serial");
	delta->uri = xmlChar2str(reader, "uri");
	delta->hash = xmlChar2str(reader, "hash");

	STAILQ_INSERT_TAIL(deltas, delta, hook);
}

static void
collect_notif_ss(xmlTextReaderPtr reader, struct notification_snapshot *ss)
{
	ss->uri = xmlChar2str(reader, "uri");
	ss->hash = xmlChar2str(reader, "hash");
}

static void
parse_notification(char const *path, struct notification *result)
{
	xmlTextReaderPtr reader;
	int read;
	xmlChar const *tag;

	reader = xmlNewTextReaderFilename(path);
	if (reader == NULL)
		panic("Can't open %s", path);

	while ((read = xmlTextReaderRead(reader)) == 1) {
		if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
			continue;

		tag = xmlTextReaderConstLocalName(reader);
		if (xmlStrEqual(tag, BAD_CAST "delta"))
			collect_notif_delta(reader, &result->deltas);
		else if (xmlStrEqual(tag, BAD_CAST "snapshot"))
			collect_notif_ss(reader, &result->snapshot);
		else if (xmlStrEqual(tag, BAD_CAST "notification"))
			collect_meta(reader, &result->meta);
	}
	if (read < 0)
		panic("Error parsing XML document.");

	xmlFreeTextReader(reader);
}

static void
collect_ss_meta(xmlTextReaderPtr reader, void *arg)
{
	struct snapshot *ss = arg;
	collect_meta(reader, &ss->meta);
}

static void
decode_base64(char *base64, unsigned char **_bin, size_t *binlen)
{
	size_t base64_len;
	size_t allocated;
	int consumed;
	int total_consumed;

	EVP_ENCODE_CTX *ctx;
	unsigned char *bin;

	int res;

	ctx = EVP_ENCODE_CTX_new();
	if (!ctx)
		panic("EVP_ENCODE_CTX_new() returned NULL");
	EVP_DecodeInit(ctx);

	base64_len = strlen(base64);
	allocated = 3 * base64_len / 4;
	bin = pmalloc(allocated);

	res = EVP_DecodeUpdate(ctx, bin, &consumed, (unsigned char *)base64, base64_len);
	if (res < 0)
		panic("EVP_DecodeUpdate(): %d", res);
	total_consumed = consumed;
	if (total_consumed > allocated)
		panic("Predicted1 %zu bytes, got %d", allocated, consumed);

	res = EVP_DecodeFinal(ctx, bin + total_consumed, &consumed);
	if (res < 0)
		panic("EVP_DecodeFinal(): %d", res);
	total_consumed += consumed;
	if (total_consumed > allocated)
		panic("Predicted2 %zu bytes, got %d", allocated, total_consumed);

	*_bin = bin;
	*binlen = total_consumed;
}

static void
collect_publish(xmlChar *uri, xmlChar *content, void *_args)
{
	struct snapshot *ss = _args;
	size_t ulen;
	struct publish *pbl;

	size_t binlen;
	unsigned char *bin;
	OCTET_STRING_t hash;

	ulen = strlen((char *)uri);
	HASH_FIND(hh, ss->publishings, uri, ulen, pbl);
	if (pbl)
		panic("Duplicate file: %s", (char *)uri);

	decode_base64((char *)content, &bin, &binlen);

	hash_sha256(bin, binlen, &hash);
	if (hash.size != HASHSIZE)
		panic("Hash lengths %zu bytes.", hash.size);

	pbl = pzalloc(sizeof(struct publish));
	pbl->uri = pstrdup((char *)uri);
	memcpy(pbl->hash, hash.buf, HASHSIZE);
	HASH_ADD_KEYPTR(hh, ss->publishings, pbl->uri, ulen, pbl);

	free(hash.buf);
	free(bin);
}

typedef void (*snapshot_cb)();
typedef void (*publish_cb)(xmlChar *, xmlChar *, void *);

static void
xml_read_publish(xmlTextReaderPtr reader, publish_cb cb, void *arg)
{
	xmlChar *uri;
	xmlChar *content;

	uri = xmlTextReaderGetAttribute(reader, BAD_CAST "uri");
	if (uri == NULL)
		panic("<publish> is missing a \"uri\" attribute.");
	if (xmlTextReaderRead(reader) != 1)
		panic("XML reader died (1) while reading '%s''s content", uri);
	content = xmlTextReaderValue(reader);
	if (content == NULL)
		panic("XML reader died (2) while reading '%s''s content", uri);

	cb(uri, content, arg);

	xmlFree(content);
	xmlFree(uri);
}

static void
foreach_ss_publish(char const *path, snapshot_cb scb, publish_cb pcb,
    void *arg)
{
	xmlTextReaderPtr reader;
	int read;
	xmlChar const *tag;

	reader = xmlNewTextReaderFilename(path);
	if (reader == NULL)
		panic("Can't open %s", path);

	while ((read = xmlTextReaderRead(reader)) == 1) {
		if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
			continue;

		tag = xmlTextReaderConstLocalName(reader);
		if (xmlStrEqual(tag, BAD_CAST "publish") && pcb)
			xml_read_publish(reader, pcb, arg);
		else if (xmlStrEqual(tag, BAD_CAST "snapshot") && scb)
			scb(reader, arg);
	}
	if (read < 0)
		panic("Error parsing XML document.");

	xmlFreeTextReader(reader);
}

unsigned long
get_serial(struct rrdp_meta *meta)
{
	unsigned long serial;

	errno = 0;
	serial = strtoul(meta->serial, NULL, 10);
	if (serial == ULONG_MAX && errno == ERANGE)
		panic("Serial is too big: %s", meta->serial);

	return serial;
}

static void
add_delta(struct deltas *deltas, enum delta_type type, struct publish *pub)
{
	struct delta *delta;
	size_t urilen;

	delta = pzalloc(sizeof(struct delta));
	delta->type = type;
	delta->uri = pub->uri;
	memcpy(delta->hash, pub->hash, HASHSIZE);

	urilen = strlen(pub->uri);
	HASH_ADD_KEYPTR(hh, deltas->ht, delta->uri, urilen, delta);
}

static void
compute_deltas(struct snapshot *ss1, struct snapshot *ss2,
    struct deltas *deltas)
{
	struct publish *pub1, *pub2, *tmp;
	size_t urilen;

	HASH_ITER(hh, ss1->publishings, pub1, tmp) {
		urilen = strlen(pub1->uri);
		HASH_FIND(hh, ss2->publishings, pub1->uri, urilen, pub2);
		if (pub2 == NULL) {
			pr_debug("%s disappeared; adding withdraw", pub1->uri);
			add_delta(deltas, DT_WITHDRAW, pub1);
		}
		else if (memcmp(pub1->hash, pub2->hash, HASHSIZE) != 0) {
			pr_debug("%s hash mismatch; adding publish", pub1->uri);
			add_delta(deltas, DT_MODIFY, pub1);
		}
	}

	HASH_ITER(hh, ss2->publishings, pub2, tmp) {
		urilen = strlen(pub2->uri);
		HASH_FIND(hh, ss1->publishings, pub2->uri, urilen, pub1);
		if (pub1 == NULL) {
			pr_debug("%s spawned; adding publish", pub2->uri);
			add_delta(deltas, DT_PUBLISH, pub2);
		}
	}
}

struct write_delta_args {
	struct deltas *deltas;
	bool new_snapshot;
	int fd;
};

static void
write_delta(xmlChar *uri, xmlChar *content, void *_args)
{
	struct write_delta_args *args = _args;
	size_t urilen;
	struct delta *delta;
	char const *tagname;

	urilen = strlen((char *)uri);
	HASH_FIND(hh, args->deltas->ht, uri, urilen, delta);
	if (delta == NULL)
		return;
	if (delta->type == DT_MODIFY && !args->new_snapshot)
		return;

	tagname = (delta->type != DT_WITHDRAW) ? "publish" : "withdraw";

	dprintf(args->fd, "  <%s uri=\"%s\"", tagname, delta->uri);
	if (delta->type != DT_PUBLISH) {
		dprintf(args->fd, " hash=\"");
		print_sha256(args->fd, delta->hash);
		dprintf(args->fd, "\"");
	}
	dprintf(args->fd, ">");
	dprintf(args->fd, "%s", content);
	dprintf(args->fd, "</%s>\n", tagname);
}

static void
write_deltas(char const *path, char const *ss1, char const *ss2,
    struct deltas *deltas)
{
	int fd;
	struct write_delta_args args;

	fd = write_open(path);

	dprintf(fd, "<delta xmlns=\"http://www.ripe.net/rpki/rrdp\"\n");
	dprintf(fd, "       version=\"%s\"\n", deltas->meta->version);
	dprintf(fd, "       session_id=\"%s\"\n", deltas->meta->session_id);
	dprintf(fd, "       serial=\"%s\">\n", deltas->meta->serial);

	args.deltas = deltas;
	args.new_snapshot = false;
	args.fd = fd;
	foreach_ss_publish(ss1, NULL, write_delta, &args);

	args.new_snapshot = true;
	foreach_ss_publish(ss2, NULL, write_delta, &args);

	dprintf(fd, "</delta>\n");

	close(fd);
}

static void
write_notification(char const *path, struct notification *new,
    char const *delta_uri, char const *delta_path)
{
	int fd;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen;
	struct notification_delta *delta;

	fd = write_open(path);

	dprintf(fd, "<notification xmlns=\"http://www.ripe.net/rpki/rrdp\"\n");
	dprintf(fd, "              version=\"%s\"\n", new->meta.version);
	dprintf(fd, "              session_id=\"%s\"\n", new->meta.session_id);
	dprintf(fd, "              serial=\"%s\">\n", new->meta.serial);

	dprintf(fd, "  <snapshot uri=\"%s\" hash=\"%s\"/>\n",
	    new->snapshot.uri, new->snapshot.hash);

	sha256_file(delta_path, hash, &hlen);
	dprintf(fd, "  <delta serial=\"%s\" uri=\"%s\" hash=\"",
	    new->meta.serial, delta_uri);
	print_sha256(fd, hash); // TODO (fine) send hlen
	dprintf(fd, "\" />\n");

	STAILQ_FOREACH(delta, &new->deltas, hook)
		dprintf(fd, "  <delta serial=\"%s\" uri=\"%s\" hash=\"%s\" />\n",
		    delta->serial, delta->uri, delta->hash);

	dprintf(fd, "</notification>\"\n");

	close(fd);
}

void
compute_delta(
    char const *notif1_path, char const *ss1_path,	/* old set */
    char const *notif2_path, char const *ss2_path,	/* new set */
    char const *notif3_path,				/* modified set */
    char const *delta_uri, char const *delta_path	/* added delta */
) {
	struct notification notif1 = { 0 };
	struct notification notif2 = { 0 };
	struct snapshot ss1 = { 0 };
	struct snapshot ss2 = { 0 };
	struct deltas deltas = { 0 };

	parse_notification(notif1_path, &notif1);
	parse_notification(notif2_path, &notif2);
	foreach_ss_publish(ss1_path, collect_ss_meta, collect_publish, &ss1);
	foreach_ss_publish(ss2_path, collect_ss_meta, collect_publish, &ss2);

	deltas.meta = &notif2.meta;
	compute_deltas(&ss1, &ss2, &deltas);
	write_deltas(delta_path, ss1_path, ss2_path, &deltas);
	write_notification(notif3_path, &notif2, delta_uri, delta_path);
}

int
main(int argc, char **argv)
{
	compute_delta(
	    "rrdp1/notification.xml", "rrdp1/notification.xml.snapshot",
	    "rrdp2/notification.xml", "rrdp2/notification.xml.snapshot",
	    "rrdp3/notification.xml",
	    "https://localhost:8080/rpki/delta.xml", "rrdp3/delta.xml"
	);
}
