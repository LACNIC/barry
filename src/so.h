#ifndef SRC_SO_H_
#define SRC_SO_H_

#include <libasn1fort/ContentInfo.h>
#include <libasn1fort/SignedData.h>
#include <libasn1fort/SignerInfo.h>
#include <libasn1fort/Manifest.h>
#include <libasn1fort/RouteOriginAttestation.h>

#include "cer.h"
#include "field.h"

extern const struct field so_metadata[];

enum so_type {
	SO_MFT,
	SO_ROA,
};

struct signed_object {
	enum so_type type;
	char *uri;
	char *path;

	ContentInfo_t ci;
	SignedData_t sd;
	struct rpki_certificate *parent;
	struct rpki_certificate ee;
	SignerInfo_t si;

	union {
		Manifest_t mft;
		RouteOriginAttestation_t roa;
	} obj;
};

struct signed_object *signed_object_new(char const *, struct rpki_certificate *,
    const int *);
void signed_object_finish(struct signed_object *, asn_TYPE_descriptor_t *);

#endif /* SRC_SO_H_ */
