#include "mft.h"

#include "asn1.h"
#include "crl.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"

static const struct field mft_metadata[] = {
	{
		"content.encapContentInfo.eContent.version",
		&ft_int,
		offsetof(struct signed_object, obj.mft.version),
		sizeof(INTEGER_t),
	}, {
		"content.encapContentInfo.eContent.manifestNumber",
		&ft_int,
		offsetof(struct signed_object, obj.mft.manifestNumber)
	}, {
		"content.encapContentInfo.eContent.thisUpdate",
		&ft_gtime,
		offsetof(struct signed_object, obj.mft.thisUpdate)
	}, {
		"content.encapContentInfo.eContent.nextUpdate",
		&ft_gtime,
		offsetof(struct signed_object, obj.mft.nextUpdate)
	}, {
		"content.encapContentInfo.eContent.fileHashAlg",
		&ft_oid,
		offsetof(struct signed_object, obj.mft.fileHashAlg)
	}, /* {
		"content.encapContentInfo.eContent.ipAddrBlocks",
		NULL,
		offsetof(Manifest_t, fileList)
	}, */
	{ 0 }
};

static struct field *mft_fields;

struct signed_object *
mft_new(char const *filename, struct rpki_certificate *parent)
{
	struct signed_object *so;
	Manifest_t *mft;

	so = signed_object_new(filename, parent, NID_id_ct_rpkiManifest);
	mft = &so->obj.mft;

	mft->version = intmax2INTEGER(0);
	init_INTEGER(&mft->manifestNumber, 1);
	init_gtime_now(&mft->thisUpdate);
	init_gtime_later(&mft->nextUpdate);
	init_oid(&mft->fileHashAlg, NID_sha256);

	return so;
}

void
mft_generate_paths(struct signed_object *so, char const *filename)
{
	so->uri = generate_uri(so->parent, filename);
	pr_debug("- uri: %s", so->uri);

	so->path = generate_path(so->parent, filename);
	pr_debug("- path: %s", so->path);

	so->parent->rpp.rpkiManifest = so->uri;
}

static void
ensure_compiled(void)
{
	if (!mft_fields) {
		fields_compile(so_metadata, &mft_fields);
		fields_compile(mft_metadata, &mft_fields);
	}
}

void
mft_apply_keyvals(struct signed_object *so, struct keyvals *kvs)
{
	ensure_compiled();
	fields_apply_keyvals(mft_fields, so, kvs);
}

void
mft_finish(struct signed_object *so, struct rpki_tree_node *siblings)
{
	Manifest_t *mft;
	unsigned int nfiles, f;
	FileAndHash_t *file;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen;
	char *path;
	struct rpki_tree_node *node, *tmp;

	pr_debug("- Creating fileList");
	mft = &so->obj.mft;
	nfiles = HASH_CNT(phook, siblings) - 1;
	f = 0;
	INIT_ASN1_ARRAY(&mft->fileList.list, nfiles, FileAndHash_t);

	HASH_ITER(phook, siblings, node, tmp) {
		switch (node->type) {
		case FT_TA:
		case FT_CER:
			path = ((struct rpki_certificate *)(node->obj))->path;
			break;
		case FT_CRL:
			path = ((struct rpki_crl *)(node->obj))->path;
			break;
		case FT_MFT:
			continue;
		case FT_ROA:
			path = ((struct signed_object *)(node->obj))->path;
			break;
		default:
			panic("Node '%s' has unknown file type: %u",
			    node->name, node->type);
		}

		file = mft->fileList.list.array[f++];
		init_8str(&file->file, node->name);
		sha256_file(path, hash, &hlen);
		file->hash.buf = pzalloc(hlen);
		memcpy(file->hash.buf, hash, hlen);
		file->hash.size = hlen;
	}

	signed_object_finish(so, &asn_DEF_Manifest);
}

void
mft_write(struct signed_object *so)
{
	asn1_write(so->path, &asn_DEF_ContentInfo, &so->ci);
}

void
mft_print(struct signed_object *so)
{
	printf("- Type: Manifest\n");
	printf("- URI : %s\n", so->uri);
	printf("- Path: %s\n", so->path);

	ensure_compiled();
	fields_print(mft_fields, so);
}
