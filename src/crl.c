#include "crl.h"

#include <stdbool.h>
#include <libasn1fort/CRLNumber.h>
#include <libasn1fort/Extension.h>
#include <libasn1fort/SignatureValue.h>

#include "alloc.h"
#include "asn1.h"
#include "ext.h"
#include "libcrypto.h"
#include "oid.h"
#include "rpki_object.h"

static void
init_extensions_crl(struct rpki_crl *crl, struct field *extf)
{
	size_t n;

	pr_debug("- Initializing CRL extensions");

	STAILQ_INIT(&crl->exts);

	n = 0;
	exts_add_aki(&crl->exts, n++, extf);
	exts_add_crln(&crl->exts, n++, extf);
}

struct rpki_crl *
crl_new(struct rpki_object *meta)
{
	struct rpki_crl *crl;
	TBSCertList_t *tbs;
	struct field *tbsf;
	struct field *extf;

	crl = pzalloc(sizeof(struct rpki_crl));
	crl->meta = meta;

	tbs = &crl->obj.tbsCertList;
	tbsf = field_add_static(meta->fields, "tbsCertList");

	tbs->version = intmax2INTEGER(1);
	field_add(tbsf, "version", &ft_int, &tbs->version, sizeof(Version_t));

	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	field_add_algorithm(tbsf, "signature", &tbs->signature);

	/* issuer: Postpone (needs parent's subject) */
	field_add(tbsf, "issuer", &ft_name, &tbs->issuer, 0);

	init_time_now(&tbs->thisUpdate);
	field_add(tbsf, "thisUpdate", &ft_time, &tbs->thisUpdate, 0);

	tbs->nextUpdate = pzalloc(sizeof(Time_t)); // TODO Needs to be nullable
	init_time_later(tbs->nextUpdate);
	field_add(tbsf, "nextUpdate", &ft_time, &tbs->nextUpdate, sizeof(struct Time));

	/* revokedCertificates: TODO not implemented yet */
	field_add(tbsf, "revokedCertificates", &ft_revoked,
	    &tbs->revokedCertificates,
	    sizeof(struct TBSCertList__revokedCertificates));

	tbs->crlExtensions = NULL;
	extf = field_add(tbsf, "crlExtensions", &ft_exts, &crl->exts, 0);
	init_extensions_crl(crl, extf);

	init_oid(&crl->obj.signatureAlgorithm.algorithm, NID_sha256WithRSAEncryption);
	crl->obj.signatureAlgorithm.parameters = create_null();
	field_add_algorithm(meta->fields, "signatureAlgorithm", &crl->obj.signatureAlgorithm);

	/* crl->signature: Postpone (needs all other fields ready) */
	field_add(meta->fields, "signature", &ft_bitstr, &crl->obj.signature, 0);

	return crl;
}

void
crl_generate_paths(struct rpki_crl *crl)
{
	crl->meta->parent->rpp.crldp = crl->meta->uri;
}

static void
update_signature(CertificateList_t *crl, EVP_PKEY *keys)
{
	SignatureValue_t signature;

	// TODO autocomputed even if overridden

	pr_debug("- Signing");
	signature = do_sign(&crl->tbsCertList, &asn_DEF_TBSCertList,
	    keys, false);
	crl->signature.buf = signature.buf;
	crl->signature.size = signature.size;
}

static void
finish_extensions(struct rpki_crl *crl)
{
	struct ext_list_node *ext;
	unsigned int extn;

	extn = 0;
	STAILQ_FOREACH(ext, &crl->exts, hook) {
		if (ext->type == EXT_AKI) {
			if (!ext_field_set(crl->meta->fields, "aki", extn, "extnValue.keyIdentifier")) {
				if (!crl->meta->parent)
					panic("CRL needs a default AKI, but lacks a parent");
				ext_finish_aki(&ext->v.aki, crl->meta->parent->spki);
			}
		}

		extn++;
	}

	ext_compile(&crl->exts, &crl->obj.tbsCertList.crlExtensions);
}

void
crl_finish(struct rpki_crl *crl)
{
	if (crl->obj.tbsCertList.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&crl->obj.tbsCertList.issuer, crl->meta->parent->subject);
	}
	finish_extensions(crl);
	update_signature(&crl->obj, crl->meta->parent->keys);
}

void
crl_write(struct rpki_crl *crl)
{
	asn1_write(crl->meta->path, &asn_DEF_CertificateList, &crl->obj);
}

void
crl_print_md(struct rpki_crl *crl)
{
	printf("- Type: CRL\n");
}

void
crl_print_csv(struct rpki_crl *crl)
{
	meta_print_csv(crl->meta, "crl");
	fields_print_csv(crl->meta->fields, crl->meta->name);
}
