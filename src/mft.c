#include "mft.h"

#include <libasn1fort/IA5String.h>

#include "asn1.h"
#include "file.h"
#include "libcrypto.h"

static void
init_filelist(Manifest_t *mft, struct rpki_tree_node *node, struct field *field)
{
	unsigned int f, c;
	FileAndHash_t *file;
	struct rpki_tree_node *sibling, *tmp;

	pr_trace("Creating fileList");

	if (node->parent == NULL)
		return; /* Leave zeroes */

	f = c = 0;
	HASH_ITER(phook, node->parent->children, sibling, tmp) {
		if (sibling->type != FT_MFT)
			f++;
		if (sibling->type == FT_CRL)
			c++;
	}
	if (c == 0)
		f++; /* The CRL will be added later */

	INIT_ASN1_ARRAY(&mft->fileList.list, f, FileAndHash_t);

	f = 0;
	HASH_ITER(phook, node->parent->children, sibling, tmp) {
		if (sibling->type == FT_MFT)
			continue;

		file = mft->fileList.list.array[f];
		init_8str(&file->file, sibling->meta.name);
		field_add_file(field, f, file, false, false);

		f++;
	}

	if (c == 0) { /* Add fields for the CRL we'll add later */
		file = mft->fileList.list.array[f];
		field_add_file(field, f, file, false, false);
	}
}

struct signed_object *
mft_new(struct rpki_tree_node *node)
{
	struct signed_object *so;
	Manifest_t *mft;
	struct field *eContent, *fileList;

	so = signed_object_new(node, NID_id_ct_rpkiManifest, &eContent);
	mft = &so->obj.mft;

	mft->version = intmax2INTEGER(0);
	field_add(eContent, "version", &ft_int, &mft->version, sizeof(INTEGER_t));

	init_INTEGER(&mft->manifestNumber, 1);
	field_add(eContent, "manifestNumber", &ft_int, &mft->manifestNumber, 0);

	init_gtime_now(&mft->thisUpdate);
	field_add(eContent, "thisUpdate", &ft_gtime, &mft->thisUpdate, 0);

	init_gtime_later(&mft->nextUpdate);
	field_add(eContent, "nextUpdate", &ft_gtime, &mft->nextUpdate, 0);

	init_oid(&mft->fileHashAlg, NID_sha256);
	field_add(eContent, "fileHashAlg", &ft_oid, &mft->fileHashAlg, 0);

	fileList = field_add(eContent, "fileList", &ft_filelist, &mft->fileList, 0);
	init_filelist(mft, node, fileList);

	return so;
}

bool
str_equals_ia5str(char const *str, IA5String_t *ia5)
{
	return (strlen(str) == ia5->size)
	    && (strncmp(str, (char *)ia5->buf, ia5->size) == 0);
}

struct rpki_tree_node *
find_sibling(struct rpki_tree_node *siblings, IA5String_t *name)
{
	struct rpki_tree_node *sibling, *tmp;

	HASH_ITER(phook, siblings, sibling, tmp)
		if (str_equals_ia5str(sibling->meta.name, name))
			return sibling;

	return NULL;
}

static void
finish_fileList(struct signed_object *so, struct rpki_tree_node *siblings)
{
	extern char const *rsync_path;

	Manifest_t *mft;
	struct field *rootf;
	int f;
	FileAndHash_t *file;
	struct rpki_tree_node *sibling;
	char *path;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen;

	mft = &so->obj.mft;
	rootf = fields_find(so->objf, "content.encapContentInfo.eContent.fileList");
	if (!rootf)
		return;

	pr_debug("- Adding missing fileList hashes");

	for (f = 0; f < mft->fileList.list.count; f++) {
		file = mft->fileList.list.array[f];
		if (file->file.size == 0) {
			pr_trace("  + filelist %d does not have a name", f);
			continue;
		}

		if (fields_overridden(fields_find_n(rootf, f), "hash")) {
			pr_trace("  + filelist %d is overridden", f);
			continue;
		}

		sibling = find_sibling(siblings, &file->file);
		if (!sibling) {
			pr_warn("I can't find %.*s (fileList %d); "
			    "its manifest hash will be left blank.",
			    (int)file->file.size, (char *)file->file.buf, f);
			continue;
		}

		pr_trace("  + filelist %d: hashing", f);

		path = join_paths(rsync_path, sibling->meta.path);
		sha256_file(path, hash, &hlen);
		free(path);

		file->hash.buf = pzalloc(hlen);
		memcpy(file->hash.buf, hash, hlen);
		file->hash.size = hlen;
	}
}

void
mft_finish(struct signed_object *so, struct rpki_tree_node *siblings)
{
	finish_fileList(so, siblings);
	signed_object_finish(so, &asn_DEF_Manifest);
}

void
mft_write(struct signed_object *so)
{
	asn1_write(so->meta->path, &asn_DEF_ContentInfo, &so->ci);
}
