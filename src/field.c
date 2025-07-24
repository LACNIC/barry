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
#include <libasn1fort/IPAddrBlocks.h>
#include <libasn1fort/PrintableString.h>
#include <libasn1fort/SignedData.h>
#include <libasn1fort/RouteOriginAttestation.h>
#include <libasn1fort/Manifest.h>

#include "alloc.h"
#include "asn1.h"
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
static error_msg const NEED_SET = "Expected a set/array value";
static error_msg const BAD_NAME = "Names are supposed to be arrays of maps whose values are strings";

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
parse_bitstr(struct kv_value *src, void *dst)
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
print_bitstr(void *val)
{
	BIT_STRING_t *str = val;
	size_t i;

	if (str->size == 0) {
		printf("0");
		return;
	}

	printf("0x");
	for (i = 0; i < str->size; i++)
		printf("%02X", str->buf[i]);

	if (str->bits_unused)
		printf("/%d", bitstr_prefix(str));
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
parse_int(struct kv_value *src, void *dst)
{
	INTEGER_t *num = dst;
	return parse_numeric_primitive(src, &num->buf, &num->size);
}

static void
print_int(void *val)
{
	INTEGER_t *num = val;
	size_t i;

	if (num->size == 0) {
		printf("0");
		return;
	}

	printf("0x");
	for (i = 0; i < num->size; i++)
		printf("%02X", num->buf[i]);
}

static int
just_print(const void *buf, size_t size, void *arg)
{
	printf("%.*s", (int)size, (char *)buf);
	return 0;
}

static void
print_int_dec(void *val)
{
	INTEGER_print(&asn_DEF_INTEGER, val, 0, just_print, NULL);
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
parse_oid(struct kv_value *src, void *oid)
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
print_oid(void *val)
{
	struct dynamic_string str = { 0 };
	char const *name;

	/* Convert OID to string */
	OBJECT_IDENTIFIER_print(&asn_DEF_OBJECT_IDENTIFIER, val, 0,
	    stringify_oid, &str);
	dstr_finish(&str);

	printf("%s", str.buf);

	name = oid2str(str.buf);
	if (name)
		printf(" (%s)", name);
}

static error_msg
parse_8str(struct kv_value *src, void *dst)
{
	OCTET_STRING_t *result = dst;
	size_t size;
	error_msg error;

	if ((error = parse_numeric_primitive(src, &result->buf, &size)) != NULL)
		return error;

	result->size = size;
	return NULL;
}

static bool
is_printable(uint8_t chr)
{
	return 31 < chr && chr < 127;
}

static void
print_printable(uint8_t *buf, size_t size)
{
	printf("\"%.*s\"", (int)size, (char *)buf);
}

static void
print_not_printable(uint8_t *buf, size_t size)
{
	size_t i;

	printf("0x");
	for (i = 0; i < size; i++)
		printf("%02X", buf[i]);
}

static void
print_maybe_string(uint8_t *buf, size_t size)
{
	size_t i;

	if (size == 0)
		return;

	if (size >= 2 && (buf[0] == 0x0C || buf[0] == 0x13 || buf[0] == 0x16)) {
		for (i = 2; i < size; i++)
			if (!is_printable(buf[i])) {
				print_not_printable(buf, size);
				return;
			}

		print_printable(buf + 2, size - 2);
		return;
	}

	print_not_printable(buf, size);
}

static void
print_8str(void *val)
{
	OCTET_STRING_t *str = val;
	print_maybe_string(str->buf, str->size);
}

static error_msg
parse_any(struct kv_value *src, void *dst)
{
	ANY_t *any = dst;
	size_t size;
	error_msg error;

	if ((error = parse_numeric_primitive(src, &any->buf, &size)) != NULL)
		return error;

	any->size = size;
	return NULL;
}

static void
print_any(void *val)
{
	ANY_t *any = val;
	print_maybe_string(any->buf, any->size);
}

static error_msg
parse_name(struct kv_value *src, void *dst)
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
print_name(void *val)
{
	Name_t *name = val;
	struct RelativeDistinguishedName *rdn;
	struct AttributeTypeAndValue *tv;
	int r, t;

	switch (name->present) {
	case Name_PR_NOTHING:
		printf("<Undefined>");
		break;

	case Name_PR_rdnSequence:
		printf("[ ");
		for (r = 0; r < name->choice.rdnSequence.list.count; r++) {
			rdn = name->choice.rdnSequence.list.array[r];
			printf("{ ");
			for (t = 0; t < rdn->list.count; t++) {
				tv = rdn->list.array[t];
				printf("\"");
				print_oid(&tv->type);
				printf("\":");
				print_any(&tv->value);
				printf(" ");
			}
			printf("} ");
		}
		printf("]");
		break;
	}
}

static error_msg
parse_time(struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		return NEED_STRING;

	init_time_str(dst, src->v.str);
	return NULL;
}

static void
print_utcTime(void *arg)
{
	time_t time;
	struct tm tm;

	time = asn_UT2time(arg, &tm, 1);
	if (time == -1) {
		printf("<Unparseable>");
		return;
	}

	printf("%04d-%02d-%02dT%02d:%02d:%02dZ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void
print_gtime(void *arg)
{
	time_t time;
	struct tm tm;

	time = asn_GT2time(arg, &tm, 1);
	if (time == -1) {
		printf("<Unparseable>");
		return;
	}

	printf("%04d-%02d-%02dT%02d:%02d:%02dZ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void
print_time(void *val)
{
	Time_t *time = val;

	switch (time->present) {
	case Time_PR_utcTime:
		print_utcTime(&time->choice.utcTime);
		break;
	case Time_PR_generalTime:
		print_gtime(&time->choice.generalTime);
		break;
	default:
		printf("<Printer not available for this data type>");
	}
}

static error_msg
parse_gtime(struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		return NEED_STRING;

	init_gtime_str(dst, src->v.str);
	return NULL;
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
parse_ips_roa(struct kv_value *src, void *arg)
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
print_pref4(IPAddress_t *addr)
{
	struct in_addr addr4 = { 0 };
	char str[INET_ADDRSTRLEN];

	memcpy(&addr4, addr->buf, addr->size);
	if (inet_ntop(AF_INET, &addr4, str, INET_ADDRSTRLEN) != NULL)
		printf("%s/%d", str, bitstr_prefix(addr));
	else
		print_bitstr(addr);
}

static void
print_pref6(IPAddress_t *addr)
{
	struct in6_addr addr6 = { 0 };
	char str[INET6_ADDRSTRLEN];

	memcpy(&addr6, addr->buf, addr->size);
	if (inet_ntop(AF_INET6, &addr6, str, INET6_ADDRSTRLEN) != NULL)
		printf("%s/%d", str, bitstr_prefix(addr));
	else
		print_bitstr(addr);
}

static void
print_pref_unknown(IPAddress_t *addr)
{
	print_bitstr(addr);
}

static void
print_array_separator(int index, int count)
{
	if (index != count - 1)
		printf(",");
	printf(" ");
}

static void
print_roa_ips(void *arg)
{
	struct RouteOriginAttestation__ipAddrBlocks *iabs = arg;
	struct ROAIPAddressFamily *riaf;
	struct ROAIPAddress *ria;
	int i, r;

	printf("[ ");
	for (i = 0; i < iabs->list.count; i++) {
		riaf = iabs->list.array[i];
		printf("[ ");

		for (r = 0; r < riaf->addresses.list.count; r++) {
			ria = riaf->addresses.list.array[r];
			if (is_v4(&riaf->addressFamily) && ria->address.size <= 4)
				print_pref4(&ria->address);
			else if (is_v6(&riaf->addressFamily) && ria->address.size <= 16)
				print_pref6(&ria->address);
			else
				print_pref_unknown(&ria->address);

			if (ria->maxLength != NULL) {
				printf("-");
				print_int_dec(ria->maxLength);
			}

			print_array_separator(r, riaf->addresses.list.count);
		}

		printf("]");
		print_array_separator(i, iabs->list.count);
	}
	printf("]");
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
parse_ips_cer(struct kv_value *src, void *arg)
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
print_cer_ips(void *arg)
{
	IPAddrBlocks_t *blocks = arg;
	IPAddressFamily_t *fam;
	IPAddressOrRange_t *aor;
	int b, a;

	void (*print_pref)(IPAddress_t *);

	printf("[ ");
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
			printf("inherit");
			break;

		case IPAddressChoice_PR_addressesOrRanges:
			printf("[ ");
			for (a = 0; a < fam->ipAddressChoice.choice.addressesOrRanges.list.count; a++) {
				aor = fam->ipAddressChoice.choice.addressesOrRanges.list.array[a];
				switch (aor->present) {
				case IPAddressOrRange_PR_NOTHING:
					panic("IPAddressOrRange_PR_NOTHING");
					break;
				case IPAddressOrRange_PR_addressPrefix:
					print_pref(&aor->choice.addressPrefix);
					break;
				case IPAddressOrRange_PR_addressRange:
					printf("<Still unimplemented>");
					break;
				}

				print_array_separator(a, fam->ipAddressChoice.choice.addressesOrRanges.list.count);
			}
			printf("]");
			break;
		}

		print_array_separator(b, blocks->list.count);
	}
	printf("]");
}

static error_msg
parse_asns_cer(struct kv_value *src, void *arg)
{
	ASIdentifiers_t *asns = arg;
	ASIdOrRange_t *aor;
	struct kv_node *node;
	int n;
	error_msg error;

	if (src->type != VALT_SET)
		return NEED_SET;

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		n++;

	asns->asnum = pzalloc(sizeof(struct ASIdentifierChoice));
	asns->asnum->present = ASIdentifierChoice_PR_asIdsOrRanges;

	INIT_ASN1_ARRAY(&asns->asnum->choice.asIdsOrRanges.list, n, struct ASIdOrRange);

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		aor = asns->asnum->choice.asIdsOrRanges.list.array[n];
		aor->present = ASIdOrRange_PR_id;
		if ((error = parse_int(&node->value, &aor->choice.id)) != NULL)
			return error;
		n++;
	}

	return NULL;

}

static void
print_asn_cer(void *arg)
{
	ASIdentifiers_t *asns = arg;
	ASIdOrRange_t *aor;
	int a;

	if (!asns->asnum) {
		printf("NULL");
		return;
	}

	switch (asns->asnum->present) {
	case ASIdentifierChoice_PR_NOTHING:
		panic("ASIdentifierChoice_PR_NOTHING");
		break;

	case ASIdentifierChoice_PR_inherit:
		printf("inherit");
		break;

	case ASIdentifierChoice_PR_asIdsOrRanges:
		printf("[ ");
		for (a = 0; a < asns->asnum->choice.asIdsOrRanges.list.count; a++) {
			aor = asns->asnum->choice.asIdsOrRanges.list.array[a];
			switch (aor->present) {
			case ASIdOrRange_PR_NOTHING:
				panic("ASIdOrRange_PR_NOTHING");
				break;
			case ASIdOrRange_PR_id:
				print_int(&aor->choice.id);
				break;
			case ASIdOrRange_PR_range:
				print_int(&aor->choice.range.min);
				printf("-");
				print_int(&aor->choice.range.max);
				break;
			}
			print_array_separator(a, asns->asnum->choice.asIdsOrRanges.list.count);
		}
		printf("]");
		break;
	}
}

static error_msg
parse_revoked_list(struct kv_value *src, void *arg)
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
		error = parse_int(
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
print_revokeds(void *arg)
{
	struct TBSCertList__revokedCertificates *rcs;
	struct TBSCertList__revokedCertificates__Member *rc;
	int i;

	rcs = *((struct TBSCertList__revokedCertificates **)arg);
	if (!rcs) {
		printf("NULL");
		return;
	}

	printf("[ ");
	for (i = 0; i < rcs->list.count; i++) {
		rc = rcs->list.array[i];
		print_int(&rc->userCertificate);

		print_array_separator(i, rcs->list.count);
	}
	printf("]");
}

const struct field_type ft_int = { "INTEGER", parse_int, print_int };
const struct field_type ft_oid = { "OBJECT_IDENTIFIER", parse_oid, print_oid };
const struct field_type ft_8str = { "OCTET_STRING", parse_8str, print_8str };
const struct field_type ft_any = { "ANY", parse_any, print_any };
const struct field_type ft_bitstr = { "BIT_STRING", parse_bitstr, print_bitstr };
const struct field_type ft_name = { "Name", parse_name, print_name };
const struct field_type ft_time = { "Time", parse_time, print_time };
const struct field_type ft_gtime = { "GeneralizedTime", parse_gtime, print_gtime };
const struct field_type ft_ip_roa = { "IP Resources (ROA)", parse_ips_roa, print_roa_ips };
const struct field_type ft_ip_cer = { "IP Resources (Certificate)", parse_ips_cer, print_cer_ips };
const struct field_type ft_asn_cer = { "AS Resources", parse_asns_cer, print_asn_cer };
const struct field_type ft_revoked = { "Revoked Certificates", parse_revoked_list, print_revokeds };

const struct field algorithm_metadata[] = {
	{
		"algorithm",
		&ft_oid,
		offsetof(AlgorithmIdentifier_t, algorithm)
	}, {
		"parameters",
		&ft_any,
		offsetof(AlgorithmIdentifier_t, parameters),
		sizeof(ANY_t)
	},
	{ 0 }
};

static void
add_ht_field(struct field **ht, char *key, size_t struct_offset,
    struct field const *proto)
{
	struct field *value;
	size_t keylen;

	value = pzalloc(sizeof(struct field));
	value->key = pstrdup(key);
	value->type = proto->type;
	value->offset = struct_offset + proto->offset;
	value->size = proto->size;

	keylen = strlen(value->key);
	HASH_ADD_KEYPTR(hh, *ht, value->key, keylen, value);
}

static void
__compile_fields(char *key, size_t key_offset, size_t struct_offset,
    struct field const *prototype, struct field **ht)
{
	struct field const *cursor;
	size_t tmpoffset;

	for (cursor = prototype; cursor->key; cursor++) {
		strcpy(key + key_offset, cursor->key);

		if (cursor->type)
			add_ht_field(ht, key, struct_offset, cursor);
		if (cursor->children) {
			tmpoffset = key_offset + strlen(cursor->key);
			key[tmpoffset] = '.';
			__compile_fields(key, tmpoffset + 1,
			    struct_offset + cursor->offset,
			    cursor->children, ht);
		}
	}
}

void
fields_compile(struct field const *metadata, struct field **ht)
{
	char key[256];
	__compile_fields(key, 0, 0, metadata, ht);
}

struct field *
fields_find(struct field *ht, char const *key)
{
	struct field *result;
	size_t keylen;

	keylen = strlen(key);
	HASH_FIND(hh, ht, key, keylen, result);

	return result;
}

static unsigned char **
get_value(struct field const *metadata, void *obj)
{
	return (unsigned char **)(((unsigned char *)obj) + metadata->offset);
}

static bool
is_pointer(struct field const *field)
{
	return field->size != 0;
}

void
fields_apply_keyvals(struct field *ht, void *target, struct keyvals *kvs)
{
	struct keyval *kv;
	struct field *field;
	unsigned char **value;
	error_msg error;

	STAILQ_FOREACH(kv, kvs, hook) {
		pr_debug("- Applying keyval: %s", kv->key);

		field = fields_find(ht, kv->key);
		if (!field)
			panic("Key '%s' is unknown.", kv->key);

		value = get_value(field, target);

		if (is_pointer(field)) {
			if (*value == NULL)
				*value = pzalloc(field->size);
			error = field->type->parser(&kv->value, *value);
		} else {
			error = field->type->parser(&kv->value, value);
		}
		if (error)
			panic("%s", error);
	}
}

void
fields_print(struct field const *metadata, void *obj)
{
	struct field const *field, *tmp;
	unsigned char **value;

	printf("\n```\n");

	HASH_ITER(hh, metadata, field, tmp) {
		if (!field->type || !field->type->print)
			continue;

		printf("%s = ", field->key);
		value = get_value(field, obj);
		if (is_pointer(field)) {
			if (*value == NULL)
				printf("NULL");
			else
				field->type->print(*value);
		} else {
			field->type->print(value);
		}
		printf("\n");
	}

	printf("```\n");
}
