#include "mft.h"

#include "asn1.h"
#include "crl.h"
#include "field.h"
#include "libcrypto.h"
#include "oid.h"

struct signed_object *
mft_new(struct rpki_object *meta)
{
	struct signed_object *so;
	Manifest_t *mft;
	struct field *eContent;

	so = signed_object_new(meta, NID_id_ct_rpkiManifest, &eContent);
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

	/* TODO fileList not implemented yet */

	return so;
}

void
mft_generate_paths(struct signed_object *so)
{
	so->meta->parent->rpp.rpkiManifest = so->meta->uri;
}

void
mft_finish(struct signed_object *so, struct rpki_tree_node *siblings)
{
	Manifest_t *mft;
	unsigned int nfiles, f;
	FileAndHash_t *file;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hlen;
	struct rpki_tree_node *node, *tmp;

	// TODO autocomputed even if overridden

	pr_debug("- Creating fileList");
	mft = &so->obj.mft;
	nfiles = HASH_CNT(phook, siblings) - 1;
	f = 0;
	INIT_ASN1_ARRAY(&mft->fileList.list, nfiles, FileAndHash_t);

	HASH_ITER(phook, siblings, node, tmp) {
		if (node->type == FT_MFT)
			continue;

		file = mft->fileList.list.array[f++];
		init_8str(&file->file, node->meta.name);
		sha256_file(node->meta.path, hash, &hlen);
		file->hash.buf = pzalloc(hlen);
		memcpy(file->hash.buf, hash, hlen);
		file->hash.size = hlen;
	}

	signed_object_finish(so, &asn_DEF_Manifest);
}

void
mft_write(struct signed_object *so)
{
	asn1_write(so->meta->path, &asn_DEF_ContentInfo, &so->ci);
}

void
mft_print(struct signed_object *so)
{
	printf("- Type: Manifest\n");
}
