#include "asn1.h"

#include <libasn1fort/AttributeTypeAndValue.h>
#include <libasn1fort/PrintableString.h>
#include <libasn1fort/RelativeDistinguishedName.h>
#include <libasn1fort/UTCTime.h>
#include <libasn1fort/ber_decoder.h>
#include <libasn1fort/der_encoder.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include "field.h"
#include "file.h"

#define BUFSIZE (64 * 1024)

void
init_8str(OCTET_STRING_t *ostr, char const *value)
{
	memset(ostr, 0, sizeof(*ostr));

	if (value) {
		ostr->buf = (uint8_t *)pstrdup(value);
		ostr->size = strlen(value);
	} else {
		ostr->buf = NULL;
		ostr->size = 0;
	}
}

INTEGER_t *
intmax2INTEGER(intmax_t src)
{
	INTEGER_t *result;
	result = pzalloc(sizeof(INTEGER_t));
	init_INTEGER(result, src);
	return result;
}

void
init_INTEGER(INTEGER_t *field, intmax_t value)
{
	if (asn_imax2INTEGER(field, value) < 0)
		panic("Unparseable INTEGER: %ld", value);
}

void
init_oid(OBJECT_IDENTIFIER_t *oid, int nid)
{
	ASN1_OBJECT *obj;
	const unsigned char *data;

	obj = OBJ_nid2obj(nid);
	if (!obj)
		panic("libcrypto does not know NID %d", nid);
	data = OBJ_get0_data(obj);
	if (!data)
		panic("libcrypto object for NID %d contains no data", nid);

	oid->size = OBJ_length(obj);
	oid->buf = pmalloc(oid->size);
	memcpy(oid->buf, data, oid->size);
}

ANY_t *
create_null(void)
{
	ANY_t *any;

	any = pzalloc(sizeof(ANY_t));
	any->size = 2;
	any->buf = pmalloc(2);
	any->buf[0] = 5;
	any->buf[1] = 0;

	return any;
}

void
init_name(Name_t *name, char const *value)
{
	struct RelativeDistinguishedName *rdn;
	struct AttributeTypeAndValue *atv;
	PrintableString_t ps;

	name->present = Name_PR_rdnSequence;
	INIT_ASN1_ARRAY(&name->choice.rdnSequence.list, 1, RelativeDistinguishedName_t);

	rdn = name->choice.rdnSequence.list.array[0];
	INIT_ASN1_ARRAY(&rdn->list, 1, AttributeTypeAndValue_t);

	atv = rdn->list.array[0];
	init_oid(&atv->type, NID_commonName);
	init_8str(&ps, value);
	der_encode_any(&asn_DEF_PrintableString, &ps, &atv->value);
}

void
init_any_str(ANY_t *any, char const *str)
{
	if (!str)
		panic("Destination ANY is NULL");

	any->buf = (uint8_t *)pstrdup(str);
	any->size = strlen(str);
}

static void
str2tm(char const *str, struct tm *tm)
{
	int res;

	memset(tm, 0, sizeof(*tm));

	res = sscanf(str, "%d-%d-%dT%d:%d:%dZ",
	    &tm->tm_year, &tm->tm_mon, &tm->tm_mday,
	    &tm->tm_hour, &tm->tm_min, &tm->tm_sec);
	if (res != 6)
		panic("Unparseable date: %s", str);
	tm->tm_mon -= 1;
	tm->tm_year -= 1900;
}

void
init_time_tm(Time_t *time, struct tm *tm)
{
	if (tm->tm_year < 150) {
		time->present = Time_PR_utcTime;
		if (asn_time2UT(&time->choice.utcTime, tm, true) == NULL)
			panic("UTCTime");
	} else {
		time->present = Time_PR_generalTime;
		if (asn_time2GT(&time->choice.generalTime, tm, true) == NULL)
			panic("GeneralizedTime");
	}
}

void
init_time_str(Time_t *time, char const *str)
{
	struct tm tm;
	str2tm(str, &tm);
	init_time_tm(time, &tm);
}

void
init_time_now(Time_t *time)
{
	extern Time_t default_now;
	*time = default_now;
}

void
init_time_later(Time_t *time)
{
	extern Time_t default_later;
	*time = default_later;
}

Time_t *
create_time(char const *str)
{
	Time_t *result;

	result = pzalloc(sizeof(Time_t));
	init_time_str(result, str);
	return result;
}

void
init_gtime_str(GeneralizedTime_t *time, char const *str)
{
	struct tm tm;
	str2tm(str, &tm);
	init_gtime_tm(time, &tm);
}

void
init_gtime_tm(GeneralizedTime_t *time, struct tm *tm)
{
	if (asn_time2GT(time, tm, true) == NULL)
		panic("GeneralizedTime");
}

void
init_gtime_now(GeneralizedTime_t *time)
{
	extern GeneralizedTime_t default_gnow;
	*time = default_gnow;
}

void
init_gtime_later(GeneralizedTime_t *time)
{
	extern GeneralizedTime_t default_glater;
	*time = default_glater;
}

void
der_encode_any(const asn_TYPE_descriptor_t *td, void *obj, ANY_t *any)
{
	asn_enc_rval_t rval;

	memset(any, 0, sizeof(*any));

	any->buf = pmalloc(BUFSIZE);

	rval = der_encode_to_buffer(td, obj, any->buf, BUFSIZE);
	if (rval.encoded < 0)
		panic("Cannot encode %s: %zd", td->name, rval.encoded);

	any->size = rval.encoded;
}

void
der_encode_8str(const asn_TYPE_descriptor_t *td, void *obj, OCTET_STRING_t *os)
{
	asn_enc_rval_t rval;

	memset(os, 0, sizeof(*os));

	os->buf = pmalloc(BUFSIZE);

	rval = der_encode_to_buffer(td, obj, os->buf, BUFSIZE);
	if (rval.encoded < 0)
		panic("Cannot encode %s: %zd", td->name, rval.encoded);

	os->size = rval.encoded;
}

void
ber2asn1(const void *ber, size_t berlen,
    const asn_TYPE_descriptor_t *td, void *asn1)
{
	asn_dec_rval_t rval;

	rval = ber_decode(NULL, td, &asn1, ber, berlen);
	if (rval.code != RC_OK)
		panic("Cannot decode %s: %u", td->name, rval.code);
}

static int
write_bytes(const void *buffer, size_t size, void *arg)
{
	int fd = *((int *)arg);
	return write(fd, buffer, size);
}

/* DER-encodes @obj (whose metadata is @td) into file @path. */
void
asn1_write(char *path, const asn_TYPE_descriptor_t *td, const void *obj)
{
	extern char const *rsync_path;
	int fd;

	path = join_paths(rsync_path, path);
	fd = write_open(path);

	der_encode(td, obj, write_bytes, &fd);

	close(fd);
	free(path);
}
