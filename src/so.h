#ifndef SRC_SO_H_
#define SRC_SO_H_

#include <libasn1fort/ContentInfo.h>
#include <libasn1fort/SignedData.h>
#include <libasn1fort/SignerInfo.h>
#include <libasn1fort/Manifest.h>
#include <libasn1fort/RouteOriginAttestation.h>

#include "cer.h"
#include "field.h"

enum so_type {
	SO_MFT,
	SO_ROA,
};

struct signed_object {
	enum so_type type;
	char *uri;
	char *path;

	struct rpki_certificate *parent;
	struct field *fields; /* Hash table */

	ContentInfo_t ci;
	SignedData_t sd;
	union {
		Manifest_t mft;
		RouteOriginAttestation_t roa;
	} obj;
	struct rpki_certificate ee;
	SignerInfo_t si;
};

struct signed_object *signed_object_new(char const *, struct rpki_certificate *,
    int);
void signed_object_finish(struct signed_object *, asn_TYPE_descriptor_t *);

#endif /* SRC_SO_H_ */
