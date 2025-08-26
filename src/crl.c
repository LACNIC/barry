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
	pr_debug("- Initializing CRL extensions");

	STAILQ_INIT(&crl->exts);

	exts_add_aki(&crl->exts, "aki", extf);
	exts_add_crln(&crl->exts, "crln", extf);
}

struct rpki_crl *
crl_new(struct rpki_tree_node *node)
{
	struct rpki_crl *crl;
	TBSCertList_t *tbs;
	struct field *tbsf;
	struct field *extf;

	crl = pzalloc(sizeof(struct rpki_crl));
	crl->meta = &node->meta;
	crl->objf = field_add(node->fields, "obj", &ft_obj, &crl->obj, 0);

	tbs = &crl->obj.tbsCertList;
	tbsf = field_add(crl->objf, "tbsCertList", &ft_obj, tbs, 0);

	tbs->version = intmax2INTEGER(1);
	field_add(tbsf, "version", &ft_int, &tbs->version, sizeof(Version_t));

	init_oid(&tbs->signature.algorithm, NID_sha256WithRSAEncryption);
	tbs->signature.parameters = create_null();
	field_add_algorithm(tbsf, "signature", &tbs->signature);

	/* issuer: Postpone (needs parent's subject) */
	field_add_name(tbsf, "issuer", &tbs->issuer);

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
	field_add_algorithm(crl->objf, "signatureAlgorithm", &crl->obj.signatureAlgorithm);

	/* crl->signature: Postpone (needs all other fields ready) */
	field_add(crl->objf, "signature", &ft_bitstr, &crl->obj.signature, 0);

	return crl;
}

static void
update_signature(struct rpki_crl *crl)
{
	SignatureValue_t signature;

	if (fields_overridden(crl->objf, "signature")) {
		pr_debug("- Skipping signature");
		return;
	}

	pr_debug("- Signing");
	signature = do_sign(&crl->obj.tbsCertList, &asn_DEF_TBSCertList,
	    crl_parent(crl)->keys, false);
	crl->obj.signature.buf = signature.buf;
	crl->obj.signature.size = signature.size;
}

static void
finish_aki(AuthorityKeyIdentifier_t *aki, struct rpki_crl *crl)
{
	struct rpki_certificate *parent;

	parent = crl_parent(crl);
	if (!parent)
		panic("CRL needs a default AKI, but lacks a parent");
	ext_finish_aki(aki, &parent->SPKI);
}

static void
finish_extensions(struct rpki_crl *crl)
{
	struct ext_list_node *ext;
	struct field *extsf;
	struct field *extnValuef;

	extsf = fields_find(crl->objf, "tbsCertList.crlExtensions");
	if (!extsf)
		panic("CRL lacks a 'tbsCertList.crlExtensions' field.");

	STAILQ_FOREACH(ext, &crl->exts, hook) {
		extnValuef = fields_find(fields_find(extsf, ext->name), "extnValue");

		if (ext->type == EXT_AKI)
			if (!fields_overridden(extnValuef, "keyIdentifier"))
				finish_aki(&ext->v.aki, crl);
	}

	ext_compile(&crl->exts, &crl->obj.tbsCertList.crlExtensions);
}

void
crl_finish(struct rpki_crl *crl)
{
	if (crl->obj.tbsCertList.issuer.present == Name_PR_NOTHING) {
		pr_debug("- Autofilling Issuer");
		init_name(&crl->obj.tbsCertList.issuer,
		    crl_parent(crl)->meta->name);
	}
	finish_extensions(crl);
	update_signature(crl);
}

void
crl_write(struct rpki_crl *crl)
{
	asn1_write(crl->meta->path, &asn_DEF_CertificateList, &crl->obj);
}

struct rpki_certificate *
crl_parent(struct rpki_crl *crl)
{
	return meta_parent(crl->meta);
}
