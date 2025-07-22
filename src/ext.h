#ifndef SRC_EXT_H_
#define SRC_EXT_H_

#include <stdbool.h>

#include <libasn1fort/Extension.h>
#include <libasn1fort/BasicConstraints.h>
#include <libasn1fort/AuthorityKeyIdentifier.h>
#include <libasn1fort/KeyUsage.h>
#include <libasn1fort/CRLDistributionPoints.h>
#include <libasn1fort/AuthorityInfoAccessSyntax.h>
#include <libasn1fort/SubjectInfoAccessSyntax.h>
#include <libasn1fort/CertificatePolicies.h>
#include <libasn1fort/IPAddrBlocks.h>
#include <libasn1fort/ASIdentifiers.h>

#include <libasn1fort/SubjectKeyIdentifier.h>
#include <libasn1fort/SubjectPublicKeyInfo.h>

void init_ext(Extension_t *, asn_TYPE_descriptor_t *, int, bool, void *);
void init_bc(BasicConstraints_t *);
void init_ski(SubjectKeyIdentifier_t *, SubjectPublicKeyInfo_t *);
void init_aki(AuthorityKeyIdentifier_t *, SubjectPublicKeyInfo_t *);
void init_ku_ca(KeyUsage_t *);
void init_ek_ee(KeyUsage_t *);
void init_gn_uri(GeneralName_t *, char const *);
void init_crldp(CRLDistributionPoints_t *, char const *);
void init_ad(AccessDescription_t *ad, int, char const *);
void init_aia(AuthorityInfoAccessSyntax_t *, char const *);
void init_sia_ca(SubjectInfoAccessSyntax_t *, char const *, char const *,
    char const *);
void init_sia_ee(SubjectInfoAccessSyntax_t *, char const *);
void init_cp(CertificatePolicies_t *);
void init_ip(IPAddrBlocks_t *);
void init_asn(ASIdentifiers_t *);

#endif /* SRC_EXT_H_ */
