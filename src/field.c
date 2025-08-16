#include "field.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <libasn1fort/ANY.h>
#include <libasn1fort/BIT_STRING.h>
#include <libasn1fort/INTEGER.h>
#include <libasn1fort/OBJECT_IDENTIFIER.h>
#include <libasn1fort/ASIdentifiers.h>
#include <libasn1fort/Certificate.h>
#include <libasn1fort/CertificateList.h>
#include <libasn1fort/ContentInfo.h>
#include <libasn1fort/Extensions.h>
#include <libasn1fort/IPAddrBlocks.h>
#include <libasn1fort/PrintableString.h>
#include <libasn1fort/SignedData.h>
#include <libasn1fort/RouteOriginAttestation.h>
#include <libasn1fort/Manifest.h>

#include "alloc.h"
#include "asn1.h"
#include "csv.h"
#include "ext.h"
#include "oid.h"
#include "print.h"
#include "str.h"

static error_msg const HEX_EMPTY = "Hexadecimal string is empty";
static error_msg const HEX_ODD_DIGITS = "Hexadecimal numbers need an even number of digits";
static error_msg const BIN_EMPTY = "Binary string is empty";
static error_msg const DEC_ERANGE = "Decimal number too large";
static error_msg const DEC_EINVAL = "Not a number";
static error_msg const PREF_TRUNC = "There are enabled bits after the prefix length";
static error_msg const PREF_LEN_2BIG = "Prefix length too long";
static error_msg const BAD_BITCOUNT = "Bit count is not a multiple of 8";
static error_msg const BITSTR_FORMAT = "Unknown BIT_STRING format";
static error_msg const BAD_OID = "Unparseable OBJECT_IDENTIFIER";
static error_msg const BAD_IP = "Unparseable IP address";
static error_msg const NEED_STRING = "Expected a string value";
static error_msg const NEED_SET = "Expected a set/array value ([brackets])";
static error_msg const NEED_MAP = "Expected a map value ({braces})";
static error_msg const BAD_NAME = "Names are supposed to be arrays of maps whose values are strings";
static error_msg const BAD_ASN = "Expected an array of AS identifiers or 'inherit'";

static error_msg
parse_obj(struct field *fields, struct kv_value *src, void *dst)
{
	return (src->type == VALT_MAP)
		? fields_apply_keyvals(fields, &src->v.map)
		: NEED_MAP;
}

static int
next_hex_digit(char const **_str)
{
	char const *str;
	char chr;

	for (str = *_str; *str != '\0' && *str != '/'; str++) {
		chr = *str;
		if ('0' <= chr && chr <= '9') {
			*_str = str + 1;
			return chr - '0';
		} else if ('a' <= chr && chr <= 'f') {
			*_str = str + 1;
			return chr - 'a' + 10;
		} else if ('A' <= chr && chr <= 'F') {
			*_str = str + 1;
			return chr - 'A' + 10;
		}
	}

	*_str = str;
	return -1;
}

static unsigned int
get_last_1_bit(int chr)
{
	unsigned int shifts;

	for (shifts = 0; shifts < 4; shifts++)
		if (chr & (1 << shifts))
			return 4 - shifts;

	return 0;
}

static error_msg
parse_bitstr_hex(char const *src, BIT_STRING_t *dst)
{
	char const *cursor;
	size_t d;
	size_t digits;
	unsigned long plen;
	int chr;

	unsigned int min_plen;

	src += 2; /* Skip "0x" */
	digits = 0;
	min_plen = 0;

	for (cursor = src; (chr = next_hex_digit(&cursor)) != -1;) {
		if (chr != 0)
			min_plen = 4 * digits + get_last_1_bit(chr);
		digits++;
	}

	if (digits == 0)
		return HEX_EMPTY;
	if (digits & 1)
		return HEX_ODD_DIGITS;

	if (*cursor == '/') {
		errno = 0;
		plen = strtoul(cursor + 1, NULL, 10);
		if ((plen == ULONG_MAX && errno == ERANGE) || plen > SIZE_MAX)
			return PREF_LEN_2BIG;
		if (plen < min_plen)
			return PREF_TRUNC;
	} else {
		plen = 4 * digits;
	}

	dst->size = (plen + 7) / 8;
	dst->buf = pzalloc(dst->size);
	dst->bits_unused = (8 - (plen & 7)) & 7;

	for (d = 0; d < dst->size; d++) {
		chr = next_hex_digit(&src);
		if (chr == -1)
			break;
		dst->buf[d] = chr << 4;

		chr = next_hex_digit(&src);
		if (chr == -1)
			break;
		dst->buf[d] |= chr;
	}

	return NULL;
}

static int
next_bin_digit(char const **_str)
{
	char const *str;

	for (str = *_str; *str != '\0' && *str != '/'; str++) {
		switch (*str) {
		case '0':
			*_str = str + 1;
			return 0;
		case '1':
			*_str = str + 1;
			return 1;
		}
	}

	*_str = str;
	return -1;
}

static error_msg
parse_bitstr_bin(char const *src, BIT_STRING_t *dst)
{
	char const *cursor;
	size_t d, b;
	size_t bits, min_plen;
	unsigned long plen;
	int chr;

	src += 2; /* Skip "0b" */
	bits = 0;
	min_plen = 0;

	for (cursor = src; (chr = next_bin_digit(&cursor)) != -1;) {
		bits++;
		if (chr == 1)
			min_plen = bits;
	}

	if (bits == 0)
		return BIN_EMPTY;

	if (*cursor == '/') {
		errno = 0;
		plen = strtoul(cursor + 1, NULL, 10);
		if ((plen == ULONG_MAX && errno == ERANGE) || plen > SIZE_MAX)
			return PREF_LEN_2BIG;
		if (plen < min_plen)
			return PREF_TRUNC;
	} else {
		plen = bits;
	}

	dst->size = (plen + 7) / 8;
	dst->buf = pzalloc(dst->size);
	dst->bits_unused = (8 - (plen & 7)) & 7;

	for (d = 0; d < dst->size; d++)
		for (b = 0; b < 8; b++) {
			chr = next_bin_digit(&src);
			if (chr == -1)
				return NULL;
			dst->buf[d] |= chr << (7 - b);
		}

	return NULL;
}

static error_msg
parse_bitstr(struct field *fields, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		return NEED_STRING;

	if (src->v.str[0] == '0' && src->v.str[1] == 'x')
		return parse_bitstr_hex(src->v.str, dst);
	if (src->v.str[0] == '0' && src->v.str[1] == 'b')
		return parse_bitstr_bin(src->v.str, dst);
	return BITSTR_FORMAT;
}

static int
bitstr_prefix(BIT_STRING_t *str)
{
	return 8 * (((int)str->size) - 1) + (8 - str->bits_unused);
}

static void
print_bitstr(struct dynamic_string *dstr, void *val)
{
	BIT_STRING_t *str = val;
	size_t i;

	if (str->size == 0) {
		dstr_append(dstr, "0");
		return;
	}

	dstr_append(dstr, "0x");
	for (i = 0; i < str->size; i++)
		dstr_append(dstr, "%02X", str->buf[i]);

	if (str->bits_unused)
		dstr_append(dstr, "/%d", bitstr_prefix(str));
}

static error_msg
parse_dec(char const *src, INTEGER_t *dst)
{
	unsigned long primitive;
	size_t srclen;

	srclen = strlen(src);

	dst->size = (srclen + 7) / 8;
	dst->buf = pmalloc(dst->size);

	errno = 0;
	primitive = strtoul(src, NULL, 10);
	if (primitive == ULONG_MAX && errno == ERANGE)
		return DEC_ERANGE;

	if (asn_ulong2INTEGER(dst, primitive) < 0)
		return DEC_EINVAL;

	return NULL;
}

static error_msg
parse_numeric_primitive(struct kv_value *src, uint8_t **buf, size_t *size)
{
	BIT_STRING_t bs;
	INTEGER_t num;
	error_msg error;

	if (src->type != VALT_STR)
		return NEED_STRING;

	if (src->v.str[0] == '0' && src->v.str[1] == 'x') {
		memset(&bs, 0, sizeof(bs));
		error = parse_bitstr_hex(src->v.str, &bs);

	} else if (src->v.str[0] == '0' && src->v.str[1] == 'b') {
		memset(&bs, 0, sizeof(bs));
		error = parse_bitstr_bin(src->v.str, &bs);

	} else {
		memset(&num, 0, sizeof(num));
		if ((error = parse_dec(src->v.str, &num)) != NULL)
			return error;
		*buf = num.buf;
		*size = num.size;
		return NULL;
	}

	if (error)
		return error;
	if ((bs.bits_unused & 7) != 0)
		return BAD_BITCOUNT;

	*buf = bs.buf;
	*size = bs.size;
	return NULL;
}

static error_msg
parse_long_int(struct kv_value *src, long int *result)
{
	INTEGER_t integer;
	long int longint;
	error_msg error;

	error = parse_numeric_primitive(src, &integer.buf, &integer.size);
	if (error)
		return error;
	if (asn_INTEGER2long(&integer, &longint) < 0)
		return "Not a number";

	*result = longint;
	return NULL;
}

static error_msg
parse_bool(struct field *fields, struct kv_value *src, void *oid)
{
	BOOLEAN_t *boolean = oid;
	long int longint;
	error_msg error;

	if (src->type == VALT_STR) {
		if (strcmp(src->v.str, "true") == 0) {
			*boolean = 0xFF;
			return NULL;
		}
		if (strcmp(src->v.str, "false") == 0) {
			*boolean = 0;
			return NULL;
		}
	}

	error = parse_long_int(src, &longint);
	if (error)
		return error;
	if (longint < INT_MIN || INT_MAX < longint)
		return "Boolean out of range";

	*boolean = (int)longint;
	return NULL;
}

static void
print_bool(struct dynamic_string *dstr, void *val)
{
	BOOLEAN_t *boolean = val;
	if (boolean != NULL)
		dstr_append(dstr, (*boolean) ? "true" : "false");
}

static error_msg
__parse_int(struct kv_value *src, INTEGER_t *dst)
{
	return parse_numeric_primitive(src, &dst->buf, &dst->size);
}

static error_msg
parse_int(struct field *fields, struct kv_value *src, void *dst)
{
	return __parse_int(src, dst);
}

static void
print_int(struct dynamic_string *dstr, void *val)
{
	INTEGER_t *num = val;
	size_t i;

	if (num->size == 0) {
		dstr_append(dstr, "0");
		return;
	}

	dstr_append(dstr, "0x");
	for (i = 0; i < num->size; i++)
		dstr_append(dstr, "%02X", num->buf[i]);
}

static int
just_print(const void *buf, size_t size, void *arg)
{
	struct dynamic_string *dstr = arg;
	dstr_append(dstr, "%.*s", (int)size, (char *)buf);
	return 0;
}

static void
print_int_dec(struct dynamic_string *dstr, void *val)
{
	INTEGER_print(&asn_DEF_INTEGER, val, 0, just_print, dstr);
}

static error_msg
parse_oid_str(char const *src, OBJECT_IDENTIFIER_t *oid)
{
	ssize_t narcs;
	asn_oid_arc_t *arcs;

	/* TODO Ugh. Maybe restore libcrypto long names */
	if (strcmp(src, "commonName") == 0) {
		oid->size = 3;
		oid->buf = pmalloc(oid->size);
		oid->buf[0] = 0x55;
		oid->buf[1] = 0x04;
		oid->buf[2] = 0x03;
		return NULL;
	}

	narcs = OBJECT_IDENTIFIER_parse_arcs(src, -1, NULL, 0, NULL);
	if (narcs < 0)
		return BAD_OID;

	arcs = calloc(narcs, sizeof(asn_oid_arc_t));
	if (!arcs)
		enomem;

	narcs = OBJECT_IDENTIFIER_parse_arcs(src, -1, arcs, narcs, NULL);
	if (narcs < 0)
		return BAD_OID;

	if (OBJECT_IDENTIFIER_set_arcs(oid, arcs, narcs) < 0)
		return BAD_OID;

	return NULL;
}

static error_msg
parse_oid(struct field *fields, struct kv_value *src, void *oid)
{
	return (src->type == VALT_STR)
	    ? parse_oid_str(src->v.str, oid)
	    : NEED_STRING;
}

static int
stringify_oid(const void *buffer, size_t size, void *arg)
{
	char const *input = buffer;

	/* asn1c prints braces for some reason; discard them. */
	if (size == 2 && ((input[0] == '{' && input[1] == ' ')))
		return 0;
	if (size == 2 && ((input[0] == ' ' && input[1] == '}')))
		return 0;

	dstr_append(arg, buffer, size);
	return 0;
}

static void
print_oid(struct dynamic_string *dstr, void *val)
{
	struct dynamic_string tmp = { 0 };
	char const *name;

	/* Convert OID to string */
	OBJECT_IDENTIFIER_print(&asn_DEF_OBJECT_IDENTIFIER, val, 0,
	    stringify_oid, &tmp);
	dstr_finish(&tmp);

	dstr_append(dstr, "%s", tmp.buf);

	name = oid2str(tmp.buf);
	if (name)
		dstr_append(dstr, " (%s)", name);

	free(tmp.buf);
}

static error_msg
parse_8str(struct field *fields, struct kv_value *src, void *dst)
{
	OCTET_STRING_t *result = dst;
	size_t size;
	error_msg error;

	if ((error = parse_numeric_primitive(src, &result->buf, &size)) != NULL)
		return error;

	result->size = size;
	return NULL;
}

static error_msg
parse_ia5str(struct field *fields, struct kv_value *src, void *dst)
{
	IA5String_t *ia5str = dst;

	if (src->type != VALT_STR)
		return NEED_STRING;

	init_8str(ia5str, src->v.str);
	return NULL;
}

static void
print_ia5str(struct dynamic_string *dstr, void *val)
{
	IA5String_t *ia5str = val;
	dstr_append(dstr, "%.*s", (int)ia5str->size, (char *)ia5str->buf);
}

static bool
is_printable(uint8_t chr)
{
	return 31 < chr && chr < 127;
}

static void
print_not_printable(struct dynamic_string *dstr, uint8_t *buf, size_t size)
{
	size_t i;

	dstr_append(dstr, "0x");
	for (i = 0; i < size; i++)
		dstr_append(dstr, "%02X", buf[i]);
}

static void
print_maybe_string(struct dynamic_string *dstr, uint8_t *buf, size_t size)
{
	size_t i;

	if (size == 0)
		return;

	print_not_printable(dstr, buf, size);

	/* Also attempt a string interpretation */
	for (i = 0; i < size; i++)
		if (!is_printable(buf[i]))
			return;
	dstr_append(dstr, " (\"%.*s\")", (int)size, (char *)(buf));
}

static void
print_8str(struct dynamic_string *dstr, void *val)
{
	OCTET_STRING_t *str = val;
	print_maybe_string(dstr, str->buf, str->size);
}

static error_msg
parse_any(struct field *fields, struct kv_value *src, void *dst)
{
	ANY_t *any = dst;
	size_t size;
	error_msg error;

	if ((error = parse_numeric_primitive(src, &any->buf, &size)) != NULL)
		return error;

	any->size = size;
	fields->children = NULL;
	return NULL;
}

static void
print_any(struct dynamic_string *dstr, void *val)
{
	ANY_t *any = val;
	print_maybe_string(dstr, any->buf, any->size);
}

static error_msg
parse_name(struct field *fields, struct kv_value *src, void *dst)
{
	struct kv_value array1;
	struct kv_node node1;
	struct keyval kv1;

	Name_t *name;
	struct RelativeDistinguishedName *rdn;
	struct AttributeTypeAndValue *atv;
	PrintableString_t ps;

	struct kv_node *node;
	struct keyval *kv;
	size_t n;
	size_t k;

	switch (src->type) {
	case VALT_STR:
		memset(&node1, 0, sizeof(node1));
		memset(&kv1, 0, sizeof(kv1));

		STAILQ_INIT(&array1.v.set);
		STAILQ_INSERT_TAIL(&array1.v.set, &node1, hook);
		node1.value.type = VALT_MAP;
		STAILQ_INIT(&node1.value.v.set);
		STAILQ_INSERT_TAIL(&node1.value.v.map, &kv1, hook);
		kv1.key = "2.5.4.3";
		kv1.value.type = VALT_STR;
		kv1.value.v.str = src->v.str;
		src = &array1;
		break;

	case VALT_SET:
		break;

	case VALT_MAP:
		return BAD_NAME;
	}

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		n++;

	name = dst;
	name->present = Name_PR_rdnSequence;
	INIT_ASN1_ARRAY(&name->choice.rdnSequence.list, n, RelativeDistinguishedName_t);

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		if (node->value.type != VALT_MAP)
			return BAD_NAME;

		k = 0;
		STAILQ_FOREACH(kv, &node->value.v.map, hook)
			k++;

		rdn = name->choice.rdnSequence.list.array[n++];
		INIT_ASN1_ARRAY(&rdn->list, k, AttributeTypeAndValue_t);

		k = 0;
		STAILQ_FOREACH(kv, &node->value.v.map, hook) {
			atv = rdn->list.array[k++];

			parse_oid_str(kv->key, &atv->type);

			if (kv->value.type != VALT_STR)
				return BAD_NAME;
			init_8str(&ps, kv->value.v.str);
			der_encode_any(&asn_DEF_PrintableString, &ps, &atv->value);
		}
	}

	return NULL;
}

static void
print_name(struct dynamic_string *dstr, void *val)
{
	Name_t *name = val;
	struct RelativeDistinguishedName *rdn;
	struct AttributeTypeAndValue *tv;
	int r, t;

	switch (name->present) {
	case Name_PR_NOTHING:
		dstr_append(dstr, "<Undefined>");
		break;

	case Name_PR_rdnSequence:
		dstr_append(dstr, "[ ");
		for (r = 0; r < name->choice.rdnSequence.list.count; r++) {
			rdn = name->choice.rdnSequence.list.array[r];
			dstr_append(dstr, "{ ");
			for (t = 0; t < rdn->list.count; t++) {
				tv = rdn->list.array[t];
				dstr_append(dstr, "\"");
				print_oid(dstr, &tv->type);
				dstr_append(dstr, "\"=");
				print_any(dstr, &tv->value);
				dstr_append(dstr, " ");
			}
			dstr_append(dstr, "} ");
		}
		dstr_append(dstr, "]");
		break;
	}
}

static error_msg
parse_time(struct field *fields, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		return NEED_STRING;

	init_time_str(dst, src->v.str);
	return NULL;
}

static void
print_utcTime(struct dynamic_string *dstr, void *arg)
{
	time_t time;
	struct tm tm;

	time = asn_UT2time(arg, &tm, 1);
	if (time == -1) {
		dstr_append(dstr, "<Unparseable>");
		return;
	}

	dstr_append(dstr, "%04d-%02d-%02dT%02d:%02d:%02dZ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void
print_gtime(struct dynamic_string *dstr, void *arg)
{
	time_t time;
	struct tm tm;

	time = asn_GT2time(arg, &tm, 1);
	if (time == -1) {
		dstr_append(dstr, "<Unparseable>");
		return;
	}

	dstr_append(dstr, "%04d-%02d-%02dT%02d:%02d:%02dZ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void
print_time(struct dynamic_string *dstr, void *val)
{
	Time_t *time = val;

	switch (time->present) {
	case Time_PR_utcTime:
		print_utcTime(dstr, &time->choice.utcTime);
		break;
	case Time_PR_generalTime:
		print_gtime(dstr, &time->choice.generalTime);
		break;
	default:
		dstr_append(dstr, "<Printer not available for this data type>");
	}
}

static error_msg
parse_gtime(struct field *fields, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		return NEED_STRING;

	init_gtime_str(dst, src->v.str);
	return NULL;
}

static bool
node_is_str(struct kv_node *node, char const *name)
{
	return strcmp(node->value.v.str, name) == 0;
}

static error_msg
parse_exts(struct field *fields, struct kv_value *src_exts, void *_dst_exts)
{
	struct extensions *dst_exts;
	struct kv_node *src_ext;
	size_t e;

	if (src_exts->type != VALT_SET)
		return NEED_SET;

	fields->children = NULL;

	e = 0;
	STAILQ_FOREACH(src_ext, &src_exts->v.set, hook)
		e++;

	dst_exts = _dst_exts;
	STAILQ_INIT(dst_exts);

	e = 0;
	STAILQ_FOREACH(src_ext, &src_exts->v.set, hook) {
		if (src_ext->value.type != VALT_STR)
			return NEED_STRING;

		if (node_is_str(src_ext, "bc"))
			exts_add_bc(dst_exts, e, fields);
		else if (node_is_str(src_ext, "ski"))
			exts_add_ski(dst_exts, e, fields);
		else if (node_is_str(src_ext, "aki"))
			exts_add_aki(dst_exts, e, fields);
		else if (node_is_str(src_ext, "ku"))
			exts_add_ku(dst_exts, e, fields);
		else if (node_is_str(src_ext, "crldp"))
			exts_add_crldp(dst_exts, e, fields);
		else if (node_is_str(src_ext, "aia"))
			exts_add_aia(dst_exts, e, fields);
		else if (node_is_str(src_ext, "sia"))
			exts_add_sia(dst_exts, e, fields);
		else if (node_is_str(src_ext, "cp"))
			exts_add_cp(dst_exts, e, fields);
		else if (node_is_str(src_ext, "ip"))
			exts_add_ip(dst_exts, e, fields);
		else if (node_is_str(src_ext, "asn"))
			exts_add_asn(dst_exts, e, fields);
		else if (node_is_str(src_ext, "crln"))
			exts_add_crln(dst_exts, e, fields);
		else
			return "Unknown extension type";

		e++;
	}

	return NULL;
}

static void
print_exts(struct dynamic_string *dstr, void *_exts)
{
	struct extensions *exts = _exts;
	struct ext_list_node *ext;
	char const *name;

	dstr_append(dstr, "[ ");
	STAILQ_FOREACH(ext, exts, hook) {
		name = NULL;
		switch (ext->type) {
		case EXT_BC:	name = "bc";		break;
		case EXT_SKI:	name = "ski";		break;
		case EXT_AKI:	name = "aki";		break;
		case EXT_KU:	name = "ku";		break;
//		case EXT_EKU:	name = "eku";		break;
		case EXT_CRLDP:	name = "crldp";		break;
		case EXT_AIA:	name = "aia";		break;
		case EXT_SIA:	name = "sia";		break;
		case EXT_CP:	name = "cp";		break;
		case EXT_IP:	name = "ip";		break;
		case EXT_ASN:	name = "asn";		break;
		case EXT_CRLN:	name = "crln";		break;
		}
		dstr_append(dstr, "%s", name);

		if (STAILQ_NEXT(ext, hook) != NULL)
			dstr_append(dstr, ", ");
	}
	dstr_append(dstr, " ]");
}

struct ip_list_node {
	unsigned int af;
	unsigned char bits[sizeof(struct in6_addr)];
	unsigned int plen;
	bool has_maxlen;
	unsigned int maxlen;

	STAILQ_ENTRY(ip_list_node) hook;
};

STAILQ_HEAD(ip_list, ip_list_node);

static unsigned int
find_last_1_index(unsigned char *bits)
{
	ssize_t i;
	size_t j;

	for (i = sizeof(struct in6_addr) - 1; i >= 0; i--)
		if (bits[i] != 0)
			for (j = 0; j < 8; j++)
				if ((bits[i] >> j) & 1)
					return 8 * i + (7 - j);

	return -1;
}

static error_msg
parse_ip_node(char *str, struct ip_list_node **result)
{
	char *slash, *dash;
	unsigned long plen;
	struct ip_list_node *ipnode;
	unsigned int index1;

	slash = strchr(str, '/');
	if (slash != NULL)
		*slash = '\0';

	ipnode = pzalloc(sizeof(struct ip_list_node));
	ipnode->af = (strchr(str, ':') != NULL) ? AF_INET6 : AF_INET;

	if (inet_pton(ipnode->af, str, ipnode->bits) < 1) {
		*slash = '/';
		return BAD_IP;
	}

	if (slash == NULL) {
		switch (ipnode->af) {
		case AF_INET:
			ipnode->plen = 32;
			break;
		case AF_INET6:
			ipnode->plen = 128;
			break;
		}
		*result = ipnode;
		return NULL;
	}

	*slash = '/';

	dash = NULL;
	errno = 0;
	plen = strtoul(slash + 1, &dash, 10);
	if ((plen == ULONG_MAX && errno == ERANGE) || plen > UINT_MAX)
		return PREF_LEN_2BIG;

	index1 = find_last_1_index(ipnode->bits);
	if (index1 != UINT_MAX && index1 >= plen)
		return PREF_TRUNC;

	ipnode->plen = plen;
	if ((*dash) != '-') {
		*result = ipnode;
		return NULL;
	}

	errno = 0;
	plen = strtoul(dash + 1, NULL, 10);
	if ((plen == ULONG_MAX && errno == ERANGE) || plen > UINT_MAX)
		return PREF_LEN_2BIG;

	ipnode->has_maxlen = true;
	ipnode->maxlen = plen;
	*result = ipnode;
	return NULL;
}

struct parsed_ips {
	struct ip_list v4list;
	unsigned int v4n;

	struct ip_list v6list;
	unsigned int v6n;
};

static error_msg
kvs2ips(struct kv_set *kvs, struct parsed_ips *ips)
{
	struct kv_node *node;
	struct ip_list_node *ipnode;
	error_msg error;

	STAILQ_INIT(&ips->v4list);
	ips->v4n = 0;
	STAILQ_INIT(&ips->v6list);
	ips->v6n = 0;

	STAILQ_FOREACH(node, kvs, hook) {
		if (node->value.type != VALT_STR)
			return NEED_STRING;
		if ((error = parse_ip_node(node->value.v.str, &ipnode)) != NULL)
			return error;

		switch (ipnode->af) {
		case AF_INET:
			STAILQ_INSERT_TAIL(&ips->v4list, ipnode, hook);
			ips->v4n++;
			break;
		case AF_INET6:
			STAILQ_INSERT_TAIL(&ips->v6list, ipnode, hook);
			ips->v6n++;
			break;
		default:
			panic("Unknown AF: %u\n", ipnode->af);
		}
	}

	return NULL;
}

static void
init_af(OCTET_STRING_t *af, int value)
{
	af->buf = pmalloc(2);
	af->buf[0] = 0;
	af->buf[1] = value;
	af->size = 2;
}

static void
node2addr(struct ip_list_node *src, IPAddress_t *dst)
{
	dst->size = (src->plen + 7) / 8;
	dst->buf = pmalloc(dst->size);
	memcpy(dst->buf, src->bits, sizeof(src->bits));
	dst->bits_unused = (8 - (src->plen & 7)) & 7;
}

static void
convert_ips(struct ROAIPAddressFamily *family, int id,
    struct ip_list *srclist, size_t n)
{
	ROAIPAddress_t *roa;
	struct ip_list_node *src;
	unsigned int i = 0;

	init_af(&family->addressFamily, id);

	INIT_ASN1_ARRAY(&family->addresses.list, n, struct ROAIPAddress);
	STAILQ_FOREACH(src, srclist, hook) {
		roa = family->addresses.list.array[i++];
		node2addr(src, &roa->address);
		if (src->has_maxlen)
			roa->maxLength = intmax2INTEGER(src->maxlen);
	}
}

static error_msg
parse_ips_roa(struct field *fields, struct kv_value *src, void *arg)
{
	struct RouteOriginAttestation__ipAddrBlocks *dst = arg;
	struct parsed_ips ips;
	error_msg error;

	if (src->type != VALT_SET)
		return NEED_SET;
	if ((error = kvs2ips(&src->v.set, &ips)) != NULL)
		return error;

	INIT_ASN1_ARRAY(&dst->list, !!ips.v4n + !!ips.v6n, struct ROAIPAddressFamily);
	if (ips.v4n)
		convert_ips(dst->list.array[0], 1, &ips.v4list, ips.v4n);
	if (ips.v6n)
		convert_ips(dst->list.array[ips.v4n ? 1 : 0], 2, &ips.v6list, ips.v6n);

	return NULL;
}

static bool
is_v4(OCTET_STRING_t *af)
{
	return af->size == 2 && af->buf[0] == 0 && af->buf[1] == 1;
}

static bool
is_v6(OCTET_STRING_t *af)
{
	return af->size == 2 && af->buf[0] == 0 && af->buf[1] == 2;
}

static void
print_pref4(struct dynamic_string *dstr, IPAddress_t *addr)
{
	struct in_addr addr4 = { 0 };
	char str[INET_ADDRSTRLEN];

	memcpy(&addr4, addr->buf, addr->size);
	if (inet_ntop(AF_INET, &addr4, str, INET_ADDRSTRLEN) != NULL)
		dstr_append(dstr, "%s/%d", str, bitstr_prefix(addr));
	else
		print_bitstr(dstr, addr);
}

static void
print_pref6(struct dynamic_string *dstr, IPAddress_t *addr)
{
	struct in6_addr addr6 = { 0 };
	char str[INET6_ADDRSTRLEN];

	memcpy(&addr6, addr->buf, addr->size);
	if (inet_ntop(AF_INET6, &addr6, str, INET6_ADDRSTRLEN) != NULL)
		dstr_append(dstr, "%s/%d", str, bitstr_prefix(addr));
	else
		print_bitstr(dstr, addr);
}

static void
print_pref_unknown(struct dynamic_string *dstr, IPAddress_t *addr)
{
	print_bitstr(dstr, addr);
}

static void
print_array_separator(struct dynamic_string *dstr, int index, int count)
{
	if (index != count - 1)
		dstr_append(dstr, ",");
	dstr_append(dstr, " ");
}

static void
print_roa_ips(struct dynamic_string *dstr, void *arg)
{
	struct RouteOriginAttestation__ipAddrBlocks *iabs = arg;
	struct ROAIPAddressFamily *riaf;
	struct ROAIPAddress *ria;
	int i, r;

	dstr_append(dstr, "[ ");
	for (i = 0; i < iabs->list.count; i++) {
		riaf = iabs->list.array[i];
		dstr_append(dstr, "[ ");

		for (r = 0; r < riaf->addresses.list.count; r++) {
			ria = riaf->addresses.list.array[r];
			if (is_v4(&riaf->addressFamily) && ria->address.size <= 4)
				print_pref4(dstr, &ria->address);
			else if (is_v6(&riaf->addressFamily) && ria->address.size <= 16)
				print_pref6(dstr, &ria->address);
			else
				print_pref_unknown(dstr, &ria->address);

			if (ria->maxLength != NULL) {
				dstr_append(dstr, "-");
				print_int_dec(dstr, ria->maxLength);
			}

			print_array_separator(dstr, r, riaf->addresses.list.count);
		}

		dstr_append(dstr, "]");
		print_array_separator(dstr, i, iabs->list.count);
	}
	dstr_append(dstr, "]");
}

static void
convert_ips_cer(struct IPAddressFamily *family, int id,
    struct ip_list *srclist, size_t n)
{
	IPAddressOrRange_t *aor;
	struct ip_list_node *src;
	unsigned int i = 0;

	init_af(&family->addressFamily, id);
	family->ipAddressChoice.present = IPAddressChoice_PR_addressesOrRanges;

	INIT_ASN1_ARRAY(&family->ipAddressChoice.choice.addressesOrRanges.list, n, struct IPAddressOrRange);
	STAILQ_FOREACH(src, srclist, hook) {
		aor = family->ipAddressChoice.choice.addressesOrRanges.list.array[i++];
		aor->present = IPAddressOrRange_PR_addressPrefix;
		node2addr(src, &aor->choice.addressPrefix);
	}
}

static error_msg
parse_ips_cer(struct field *fields, struct kv_value *src, void *arg)
{
	IPAddrBlocks_t *dst = arg;
	struct parsed_ips ips;
	error_msg error;

	if (src->type != VALT_SET)
		return NEED_SET;
	if ((error = kvs2ips(&src->v.set, &ips)) != NULL)
		return error;

	INIT_ASN1_ARRAY(&dst->list, !!ips.v4n + !!ips.v6n, struct IPAddressFamily);
	if (ips.v4n)
		convert_ips_cer(dst->list.array[0], 1, &ips.v4list, ips.v4n);
	if (ips.v6n)
		convert_ips_cer(dst->list.array[ips.v4n ? 1 : 0], 2, &ips.v6list, ips.v6n);

	return NULL;
}

static void
print_cer_ips(struct dynamic_string *dstr, void *arg)
{
	IPAddrBlocks_t *blocks = arg;
	IPAddressFamily_t *fam;
	IPAddressOrRange_t *aor;
	int b, a;

	void (*print_pref)(struct dynamic_string *, IPAddress_t *);

	dstr_append(dstr, "[ ");
	for (b = 0; b < blocks->list.count; b++) {
		fam = blocks->list.array[b];

		if (is_v4(&fam->addressFamily))
			print_pref = print_pref4;
		else if (is_v6(&fam->addressFamily))
			print_pref = print_pref6;
		else
			print_pref = print_pref_unknown;

		switch (fam->ipAddressChoice.present) {
		case IPAddressChoice_PR_NOTHING:
			panic("IPAddressChoice_PR_NOTHING");
			break;

		case IPAddressChoice_PR_inherit:
			dstr_append(dstr, "inherit");
			break;

		case IPAddressChoice_PR_addressesOrRanges:
			dstr_append(dstr, "[ ");
			for (a = 0; a < fam->ipAddressChoice.choice.addressesOrRanges.list.count; a++) {
				aor = fam->ipAddressChoice.choice.addressesOrRanges.list.array[a];
				switch (aor->present) {
				case IPAddressOrRange_PR_NOTHING:
					panic("IPAddressOrRange_PR_NOTHING");
					break;
				case IPAddressOrRange_PR_addressPrefix:
					print_pref(dstr, &aor->choice.addressPrefix);
					break;
				case IPAddressOrRange_PR_addressRange:
					// TODO not implemented yet
					dstr_append(dstr, "<Still unimplemented>");
					break;
				}

				print_array_separator(dstr, a, fam->ipAddressChoice.choice.addressesOrRanges.list.count);
			}
			dstr_append(dstr, "]");
			break;
		}

		print_array_separator(dstr, b, blocks->list.count);
	}
	dstr_append(dstr, "]");
}

static error_msg
parse_asns_str(struct kv_value *src, ASIdentifierChoice_t *dst)
{
	if (strcmp("inherit", src->v.str) != 0)
		return "Expected an array of AS identifiers or 'inherit'";

	dst->present = ASIdentifierChoice_PR_inherit;
	return NULL;
}

static error_msg
parse_asns_set(struct kv_value *src, ASIdentifierChoice_t *aic)
{
	struct kv_node *node;
	ASIdOrRange_t *aor;
	int n;
	error_msg error;

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		n++;

	aic->present = ASIdentifierChoice_PR_asIdsOrRanges;
	INIT_ASN1_ARRAY(&aic->choice.asIdsOrRanges.list, n, struct ASIdOrRange);

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		aor = aic->choice.asIdsOrRanges.list.array[n++];
		aor->present = ASIdOrRange_PR_id;
		error = __parse_int(&node->value, &aor->choice.id);
		if (error)
			return error;
	}

	return NULL;
}

static error_msg
parse_asns(struct field *fields, struct kv_value *src, void *arg)
{
	switch (src->type) {
	case VALT_STR:
		return parse_asns_str(src, arg);
	case VALT_SET:
		return parse_asns_set(src, arg);
	case VALT_MAP:
		break;
	}

	return BAD_ASN;
}

static void
print_asns(struct dynamic_string *dstr, void *arg)
{
	ASIdentifierChoice_t *aic = arg;
	ASIdOrRange_t *aor;
	int a;

	if (!aic)
		return;

	switch (aic->present) {
	case ASIdentifierChoice_PR_NOTHING:
		panic("ASIdentifierChoice_PR_NOTHING");
		break;

	case ASIdentifierChoice_PR_inherit:
		dstr_append(dstr, "inherit");
		break;

	case ASIdentifierChoice_PR_asIdsOrRanges:
		dstr_append(dstr, "[ ");
		for (a = 0; a < aic->choice.asIdsOrRanges.list.count; a++) {
			aor = aic->choice.asIdsOrRanges.list.array[a];
			switch (aor->present) {
			case ASIdOrRange_PR_NOTHING:
				panic("ASIdOrRange_PR_NOTHING");
				break;
			case ASIdOrRange_PR_id:
				print_int(dstr, &aor->choice.id);
				break;
			case ASIdOrRange_PR_range:
				print_int(dstr, &aor->choice.range.min);
				dstr_append(dstr, "-");
				print_int(dstr, &aor->choice.range.max);
				break;
			}
			print_array_separator(dstr, a, aic->choice.asIdsOrRanges.list.count);
		}
		dstr_append(dstr, "]");
		break;
	}
}

static error_msg
parse_revoked_list(struct field *fields, struct kv_value *src, void *arg)
{
	struct TBSCertList__revokedCertificates *rcs;
	struct kv_node *node;
	int n;
	error_msg error;

	if (src->type != VALT_SET)
		return NEED_SET;

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		n++;

	rcs = pzalloc(sizeof(struct TBSCertList__revokedCertificates));
	*((struct TBSCertList__revokedCertificates **)arg) = rcs;

	INIT_ASN1_ARRAY(
	    &rcs->list, n,
	    struct TBSCertList__revokedCertificates__Member
	);

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		error = __parse_int(
		    &node->value,
		    &rcs->list.array[n]->userCertificate
		);
		if (error)
			return error;
		n++;
	}

	return NULL;
}

static void
print_revokeds(struct dynamic_string *dstr, void *arg)
{
	struct TBSCertList__revokedCertificates *rcs;
	struct TBSCertList__revokedCertificates__Member *rc;
	int i;

	rcs = *((struct TBSCertList__revokedCertificates **)arg);
	if (!rcs)
		return;

	dstr_append(dstr, "[ ");
	for (i = 0; i < rcs->list.count; i++) {
		rc = rcs->list.array[i];
		print_int(dstr, &rc->userCertificate);

		print_array_separator(dstr, i, rcs->list.count);
	}
	dstr_append(dstr, "]");
}

static void
add_filelist_fields(struct field *parentf, struct Manifest__fileList *filelist,
    bool name_overridden, bool hash_overridden)
{
	int f;
	for (f = 0; f < filelist->list.count; f++)
		field_add_file(parentf, f, filelist->list.array[f],
		    name_overridden, hash_overridden);
}

static error_msg
parse_filelist_str(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	long int count;
	error_msg error;

	error = parse_long_int(src, &count);
	if (error)
		return error;
	if (count < 0 || SIZE_MAX < count)
		return "Filelist length out of range";

	INIT_ASN1_ARRAY(&filelist->list, count, FileAndHash_t);
	add_filelist_fields(rootf, filelist, false, false);
	return NULL;
}

static error_msg
parse_filelist_set(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	struct kv_node *node;
	size_t f;

	f = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		if (node->value.type != VALT_STR)
			return "fileList entry is not a string";
		f++;
	}

	INIT_ASN1_ARRAY(&filelist->list, f, FileAndHash_t);
	f = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		init_8str(&filelist->list.array[f++]->file, node->value.v.str);

	add_filelist_fields(rootf, filelist, true, false);
	return NULL;
}

static error_msg
parse_filelist_map(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	struct keyval *kv;
	FileAndHash_t *fah;
	int f;

	f = 0;
	STAILQ_FOREACH(kv, &src->v.map, hook) {
		if (kv->value.type != VALT_STR)
			return "fileList entry is not a string";
		f++;
	}

	INIT_ASN1_ARRAY(&filelist->list, f, FileAndHash_t);
	f = 0;
	STAILQ_FOREACH(kv, &src->v.map, hook) {
		fah = filelist->list.array[f++];
		init_8str(&fah->file, kv->key);
		parse_bitstr(NULL, &kv->value, &fah->hash);
	}

	add_filelist_fields(rootf, filelist, true, true);
	return NULL;
}

static error_msg
parse_filelist(struct field *rootf, struct kv_value *src, void *arg)
{
	error_msg error = NULL;

	rootf->children = NULL;

	switch (src->type) {
	case VALT_STR:	error = parse_filelist_str(rootf, src, arg);	break;
	case VALT_SET:	error = parse_filelist_set(rootf, src, arg);	break;
	case VALT_MAP:	error = parse_filelist_map(rootf, src, arg);	break;
	}

	return error;
}

static void
print_filelist(struct dynamic_string *dstr, void *arg)
{
	struct Manifest__fileList *filelist = arg;
	FileAndHash_t *fah;
	int f;

	dstr_append(dstr, "{ ");

	for (f = 0; f < filelist->list.count; f++) {
		fah = filelist->list.array[f];
		print_ia5str(dstr, &fah->file);
		dstr_append(dstr, "=");
		print_bitstr(dstr, &fah->hash);

		print_array_separator(dstr, f, filelist->list.count);
	}

	dstr_append(dstr, "}");
}

const struct field_type ft_obj = { "Object", parse_obj, NULL };
const struct field_type ft_bool = { "BOOLEAN", parse_bool, print_bool };
const struct field_type ft_int = { "INTEGER", parse_int, print_int };
const struct field_type ft_oid = { "OBJECT IDENTIFIER", parse_oid, print_oid };
const struct field_type ft_8str = { "OCTET STRING", parse_8str, print_8str };
const struct field_type ft_ia5str = { "IA5String", parse_ia5str, print_ia5str };
const struct field_type ft_any = { "ANY", parse_any, print_any };
const struct field_type ft_bitstr = { "BIT STRING", parse_bitstr, print_bitstr };
const struct field_type ft_name = { "Name", parse_name, print_name };
const struct field_type ft_time = { "Time", parse_time, print_time };
const struct field_type ft_gtime = { "GeneralizedTime", parse_gtime, print_gtime };
const struct field_type ft_exts = { "Extensions", parse_exts, print_exts };
const struct field_type ft_ip_roa = { "IP Resources (ROA)", parse_ips_roa, print_roa_ips };
const struct field_type ft_ip_cer = { "IP Resources (Certificate)", parse_ips_cer, print_cer_ips };
const struct field_type ft_asn_cer = { "AS Resources", parse_asns, print_asns };
const struct field_type ft_revoked = { "Revoked Certificates", parse_revoked_list, print_revokeds };
const struct field_type ft_filelist = { "File List", parse_filelist, print_filelist };

struct field *
__field_add(struct field *parent, char const *name)
{
	struct field *new;
	size_t namelen;

	new = pzalloc(sizeof(struct field));
	new->key = name;

	namelen = strlen(name);
	HASH_ADD_KEYPTR(hh, parent->children, name, namelen, new);

	return new;
}

static void
n2str(size_t n, char *str)
{
	int written;

	written = snprintf(str, 20, "%zu", n);
	if (written < 0 || written >= 20)
		panic("snprintf(%zu): %d", n, written);
}

struct field *
field_addn(struct field *parent, size_t n,
    struct field_type const *type, void *address, size_t size)
{
	char buf[20];
	struct field *result;

	n2str(n, buf);

	result = field_add(parent, pstrdup(buf), type, address, size);
	/* result->invisible = true; */
	return result;
}

struct field *
field_add(struct field *parent, char const *name,
    struct field_type const *type, void *address, size_t size)
{
	struct field *new;

	new = __field_add(parent, name);
	new->type = type;
	new->address = address;
	new->size = size;

	return new;
}

struct field *
field_add_algorithm(struct field *parent, char const *name,
    AlgorithmIdentifier_t *value)
{
	struct field *new;

	new = field_add(parent, name, &ft_obj, value, 0);
	field_add(new, "algorithm", &ft_oid, &value->algorithm, 0);
	field_add(new, "parameters", &ft_any, &value->parameters,
	    sizeof(ANY_t));

	return new;
}

struct field *
field_add_spki(struct field *parent, char const *name,
    SubjectPublicKeyInfo_t *value)
{
	struct field *new;

	new = field_add(parent, name, &ft_obj, value, 0);
	field_add_algorithm(new, "algorithm", &value->algorithm);
	field_add(new, "subjectPublicKey", &ft_bitstr, &value->subjectPublicKey, 0);

	return new;
}

void
field_add_file(struct field *filelist, size_t f, struct FileAndHash *fah,
    bool name_overridden, bool hash_overridden)
{
	struct field *numf, *child;

	numf = field_addn(filelist, f, &ft_obj, fah, 0);
	child = field_add(numf, "file", &ft_ia5str, &fah->file, 0);
	child->overridden = name_overridden;
	child = field_add(numf, "hash", &ft_bitstr, &fah->hash, 0);
	child->overridden = hash_overridden;
}

struct field *
fields_find(struct field *root, char const *key)
{
	struct field *parent, *child;
	char const *dot;
	size_t keylen;

	parent = root;

	do {
		dot = strchr(key, '.');
		if (!dot) {
			keylen = strlen(key);
			HASH_FIND(hh, parent->children, key, keylen, child);
			return child;
		}

		keylen = dot - key;
		HASH_FIND(hh, parent->children, key, keylen, child);
		if (child == NULL)
			return NULL;

		key = dot + 1;
		parent = child;
	} while (true);
}

struct field *
fields_find_n(struct field *parent, size_t n)
{
	char buf[20];
	n2str(n, buf);
	return fields_find(parent, buf);
}

bool
fields_overridden(struct field *root, char const *key)
{
	struct field *node;

	if (!root)
		return false;

	node = fields_find(root, key);
	return node ? node->overridden : false;
}

static bool
is_pointer(struct field const *field)
{
	return field->size != 0;
}

error_msg
fields_apply_keyvals(struct field *ht, struct keyvals *kvs)
{
	struct keyval *kv;
	struct field *field;
	unsigned char **value;
	error_msg error;

	STAILQ_FOREACH(kv, kvs, hook) {
		pr_trace("keyval: %s", kv->key);

		field = fields_find(ht, kv->key);
		if (!field)
			panic("Key '%s' is unknown.", kv->key);
		if (!field->type || !field->type->parser)
			panic("I don't have a parser for '%s'", kv->key);

		value = field->address;
		if (is_pointer(field)) {
			if (*value == NULL)
				*value = pzalloc(field->size);
			error = field->type->parser(field, &kv->value, *value);
		} else {
			error = field->type->parser(field, &kv->value, value);
		}
		if (error)
			return error;

		field->overridden = true;
	}

	return NULL;
}

static void
__fields_print(struct field const *field, char *key, size_t key_offset)
{
	struct field *child, *tmp;
	unsigned char **address;
	struct dynamic_string dstr = { 0 };

	if (field->invisible)
		return;

	strcpy(key + key_offset, field->key);

	if (field->type && field->type->print) {
		address = field->address;
		if (is_pointer(field)) {
			if (*address != NULL)
				field->type->print(&dstr, *address);
		} else {
			field->type->print(&dstr, address);
		}

		printf("%s = %s\n", key, dstr_finish(&dstr));
		dstr_cleanup(&dstr);
	}

	key_offset += strlen(field->key);
	key[key_offset] = '.';
	HASH_ITER(hh, field->children, child, tmp)
		__fields_print(child, key, key_offset + 1);
}

void
fields_print_md(struct field const *root)
{
	struct field const *child, *tmp;
	char key[FIELD_MAXLEN];

	printf("```\n");
	HASH_ITER(hh, root->children, child, tmp)
		__fields_print(child, key, 0);
	printf("```\n");
}

static void
__fields_print_csv(char const *name, struct field const *field,
    char *key, size_t key_offset)
{
	struct field *child, *tmp;
	unsigned char **address;
	struct dynamic_string dstr = { 0 };

	if (field->invisible)
		return;
	strcpy(key + key_offset, field->key);

	if (field->type && field->type->print) {
		address = field->address;
		if (is_pointer(field)) {
			if (*address != NULL)
				field->type->print(&dstr, *address);
		} else {
			field->type->print(&dstr, address);
		}

		csv_print(name, ',');
		csv_print(key, ',');
		csv_print(field->type->name, ',');
		csv_print(dstr_finish(&dstr), '\n');

		dstr_cleanup(&dstr);
	}

	key_offset += strlen(field->key);
	key[key_offset] = '.';
	HASH_ITER(hh, field->children, child, tmp)
		__fields_print_csv(name, child, key, key_offset + 1);
}

void
fields_print_csv(struct field const *fields, char const *name)
{
	struct field const *field, *tmp;
	char key[FIELD_MAXLEN];

	HASH_ITER(hh, fields->children, field, tmp)
		__fields_print_csv(name, field, key, 0);
}
