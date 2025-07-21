#include "asn1.h"

#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libasn1fort/AttributeTypeAndValue.h>
#include <libasn1fort/PrintableString.h>
#include <libasn1fort/RelativeDistinguishedName.h>

#include "alloc.h"
#include "oid.h"
#include "print.h"

#define BUFSIZE 4096

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
init_oid(OBJECT_IDENTIFIER_t *oid, int const *raw)
{
	size_t i;

	for (i = 0; raw[i]; i++)
		;

	oid->size = i;
	oid->buf = pmalloc(i);
	for (i = 0; i < oid->size; i++)
		oid->buf[i] = raw[i];
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
	name->choice.rdnSequence.list.count = 1;
	name->choice.rdnSequence.list.size = name->choice.rdnSequence.list.count * sizeof(struct RelativeDistinguishedName *);
	name->choice.rdnSequence.list.array = pmalloc(name->choice.rdnSequence.list.size);

	rdn = pzalloc(sizeof(struct RelativeDistinguishedName));
	name->choice.rdnSequence.list.array[0] = rdn;

	rdn->list.count = 1;
	rdn->list.size = rdn->list.count * sizeof(struct AttributeTypeAndValue *);
	rdn->list.array = pmalloc(rdn->list.size);

	atv = pzalloc(sizeof(struct AttributeTypeAndValue));
	rdn->list.array[0] = atv;
	init_oid(&atv->type, OID_COMMON_NAME);
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

void *
decode_ber(const asn_TYPE_descriptor_t *td, const void *bin, size_t binlen)
{
	void *result;
	asn_dec_rval_t rval;

	result = NULL;
	rval = ber_decode(NULL, td, &result, bin, binlen);
	if (rval.code != RC_OK)
		panic("Cannot decode %s: %u", td->name, rval.code);

	return result;
}

void *
decode_ext(const asn_TYPE_descriptor_t *td, struct Extension *ext)
{
	return decode_ber(td, ext->extnValue.buf, ext->extnValue.size);
}

static int
write_bytes(const void *buffer, size_t size, void *arg)
{
	int fd = *((int *)arg);
	return write(fd, buffer, size);
}

/* Does not care if the path already exists. */
void
exec_mkdir(char *path)
{
	pr_trace("mkdir '%s'", path);
	if (mkdir(path, 0750) < 0 && errno != EEXIST)
		panic("mkdir(%s): %s", path, strerror(errno));
}

/* Does not care if the path already exists, automatically creates parents. */
void
exec_mkdir_p(char const *_path, bool include_last)
{
	char *path, *slash;

	if (_path == NULL)
		panic("Path is NULL.");
	if (_path[0] == '\0')
		panic("Path is empty.");

	path = pstrdup(_path);
	slash = path;

	while ((slash = strchr(slash + 1, '/')) != NULL) {
		*slash = '\0';
		exec_mkdir(path);
		*slash = '/';
	};

	if (include_last)
		exec_mkdir(path);

	free(path);
}

/* DER-encodes @obj (whose metadata is @td) into file @path. */
void
asn1_write(char *path, const asn_TYPE_descriptor_t *td, const void *obj)
{
	int fd;

	pr_trace("echo 'Beep boop' > %s", path);

	fd = open(path, O_WRONLY | O_CREAT, 0640);
	if (fd < 0) {
		if (errno == ENOENT) {
			exec_mkdir_p(path, false);
			fd = open(path, O_WRONLY | O_CREAT, 0640);
			if (fd < 0)
				goto ouch;
		} else {
ouch:			panic("open(%s): %s", path, strerror(errno));
		}
	}

	der_encode(td, obj, write_bytes, &fd);

	close(fd);
}
