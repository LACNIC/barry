#ifndef SRC_EXT_H_
#define SRC_EXT_H_

#include <stdbool.h>
#include <sys/queue.h>

#include <libasn1fort/Extensions.h>
#include <libasn1fort/BasicConstraints.h>
#include <libasn1fort/AuthorityKeyIdentifier.h>
#include <libasn1fort/KeyUsage.h>
#include <libasn1fort/CRLDistributionPoints.h>
#include <libasn1fort/CRLNumber.h>
#include <libasn1fort/AuthorityInfoAccessSyntax.h>
#include <libasn1fort/SubjectInfoAccessSyntax.h>
#include <libasn1fort/CertificatePolicies.h>
#include <libasn1fort/IPAddrBlocks.h>
#include <libasn1fort/ASIdentifiers.h>

#include <libasn1fort/SubjectKeyIdentifier.h>
#include <libasn1fort/SubjectPublicKeyInfo.h>

#include "field.h"

enum cer_type {
	CT_TA,
	CT_CA,
	CT_EE,
};

enum ext_type {
	EXT_BC,
	EXT_SKI,
	EXT_AKI,
	EXT_KU,
//	EXT_EKU,
	EXT_CRLDP,
	EXT_AIA,
	EXT_SIA,
	EXT_CP,
	EXT_IP,
	EXT_ASN,
	EXT_CRLN,
};

struct ext_list_node {
	enum ext_type type;
	const asn_TYPE_descriptor_t *td;
	char *name;

	OBJECT_IDENTIFIER_t extnID;
	BOOLEAN_t critical;

	union {
		BasicConstraints_t bc;
		SubjectKeyIdentifier_t ski;
		AuthorityKeyIdentifier_t aki;
		KeyUsage_t ku;
		CRLDistributionPoints_t crldp;
		AuthorityInfoAccessSyntax_t aia;
		SubjectInfoAccessSyntax_t sia;
		CertificatePolicies_t cp;
		IPAddrBlocks_t ip;
		ASIdentifiers_t asn;
		CRLNumber_t crln;
	} v;

	STAILQ_ENTRY(ext_list_node) hook;
};

STAILQ_HEAD(extensions, ext_list_node);

void exts_add_bc(struct extensions *, char const *, struct field *);
void exts_add_ski(struct extensions *, char const *, struct field *);
void exts_add_aki(struct extensions *, char const *, struct field *);
void exts_add_ku(struct extensions *, char const *, struct field *);
void exts_add_crldp(struct extensions *, char const *, struct field *);
void exts_add_aia(struct extensions *, char const *, struct field *);
void exts_add_sia(struct extensions *, char const *, struct field *);
void exts_add_cp(struct extensions *, char const *, struct field *);
void exts_add_ip(struct extensions *, char const *, struct field *);
void exts_add_asn(struct extensions *, char const *, struct field *);
void exts_add_crln(struct extensions *, char const *, struct field *);

void ext_finish_ski(SubjectKeyIdentifier_t *, SubjectPublicKeyInfo_t *);
void ext_finish_aki(AuthorityKeyIdentifier_t *, SubjectPublicKeyInfo_t *);
void ext_finish_ku(KeyUsage_t *, enum cer_type);
void ext_finish_crldp(CRLDistributionPoints_t *, char const *);
void ext_finish_aia(AuthorityInfoAccessSyntax_t *, char const *);
void ext_finish_sia_ca(SubjectInfoAccessSyntax_t *, char const *, char const *,
    char const *);
void ext_finish_sia_ee(SubjectInfoAccessSyntax_t *, char const *);
void ext_finish_cp(CertificatePolicies_t *);
void ext_finish_ip(IPAddrBlocks_t *);
void ext_finish_asn(ASIdentifiers_t *);

void ext_compile(struct extensions *, Extensions_t **);

#endif /* SRC_EXT_H_ */
