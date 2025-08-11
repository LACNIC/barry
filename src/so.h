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
	struct rpki_object *meta;

	enum so_type type;

	ContentInfo_t ci;
	SignedData_t sd;
	union {
		Manifest_t mft;
		RouteOriginAttestation_t roa;
	} obj;
	struct rpki_certificate ee;
	struct rpki_object ee_meta;
	SignerInfo_t si;
};

struct signed_object *signed_object_new(struct rpki_object *, int,
    struct field **);
void signed_object_finish(struct signed_object *, asn_TYPE_descriptor_t *);
void so_print_csv(struct signed_object *);

#endif /* SRC_SO_H_ */
