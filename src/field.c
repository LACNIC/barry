#include "field.h"

#include <errno.h>
#include <libasn1fort/ASIdOrRange.h>
#include <libasn1fort/ASIdentifierChoice.h>
#include <libasn1fort/AttributeTypeAndValue.h>
#include <libasn1fort/BIT_STRING.h>
#include <libasn1fort/IPAddress.h>
#include <libasn1fort/IPAddressFamily.h>
#include <libasn1fort/IPAddressOrRange.h>
#include <libasn1fort/Manifest.h>
#include <libasn1fort/PrintableString.h>
#include <libasn1fort/ProviderASSet.h>
#include <libasn1fort/ROAIPAddress.h>
#include <libasn1fort/ROAIPAddressFamily.h>
#include <libasn1fort/RelativeDistinguishedName.h>
#include <libasn1fort/RouteOriginAttestation.h>
#include <libasn1fort/TBSCertList.h>
#include <libasn1fort/UTCTime.h>
#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asn1.h"
#include "csv.h"
#include "ext.h"
#include "oid.h"
#include "rpki_tree.h"

#define DEC_EINVAL(k, v) panic("'%s' cannot be parsed as a number: %s", k, v)
#define PREF_TRUNC(k, v) panic("'%s' has enabled bits after the prefix length: %s", k, v)
#define PREF_LEN_2BIG(k, v) panic("'%s' prefix length is too long: %s", k, v)
#define BAD_OID(k, v) panic("'%s' is an unparseable OBJECT_IDENTIFIER: %s", k, v)
#define NEED_STRING(k) panic("'%s': Expected a string value.", k)
#define NEED_SET(k) panic("'%s': Expected a set/array value. ([brackets])", k)
#define NEED_MAP(k) panic("'%s': Expected a map value. ({braces})", k)
#define NEED_STR_OR_MAP(k) panic("'%s': Expected a string or map. ({braces})", k)
#define NEED_SET_OR_MAP(k) panic("'%s': Expected a set/array ([brackets]) or map ({braces}).", k)
#define BAD_IPS(k) panic("'%s': Expected an array of IPs or 'inherit'", k)
#define BAD_ASN(k) panic("'%s': Expected an array of AS identifiers or 'inherit'", k)

static void
parse_obj(struct field *field, struct kv_value *src, void *dst)
{
	if (src->type != VALT_MAP)
		NEED_MAP(field->key);

	fields_apply_keyvals(field, &src->v.map);
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

static void
parse_bitstr_hex(struct field *field, char const *_src, BIT_STRING_t *dst)
{
	char const *src;
	char const *cursor;
	size_t d;
	size_t digits;
	unsigned long plen;
	char *endptr;
	int chr;

	unsigned int min_plen;

	src = _src + 2; /* Skip "0x" */
	digits = 0;
	min_plen = 0;

	for (cursor = src; (chr = next_hex_digit(&cursor)) != -1;) {
		if (chr != 0)
			min_plen = 4 * digits + get_last_1_bit(chr);
		digits++;
	}

	if (digits == 0)
		panic("'%s' hexadecimal string is empty: %s",
		    field->key, _src);
	if (digits & 1)
		panic("'%s' hex number needs an even number of digits: %s",
		    field->key, _src);

	if (*cursor == '/') {
		errno = 0;
		plen = strtoul(cursor + 1, &endptr, 10);
		if ((plen == ULONG_MAX && errno == ERANGE) || plen > SIZE_MAX)
			PREF_LEN_2BIG(field->key, _src);
		if (cursor + 1 == endptr)
			DEC_EINVAL(field->key, cursor + 1);
		if (plen < min_plen)
			PREF_TRUNC(field->key, _src);
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

static void
parse_bitstr_bin(struct field *field, char const *_src, BIT_STRING_t *dst)
{
	char const *src;
	char const *cursor;
	size_t d, b;
	size_t bits, min_plen;
	unsigned long plen;
	char *endptr;
	int chr;

	src = _src + 2; /* Skip "0b" */
	bits = 0;
	min_plen = 0;

	for (cursor = src; (chr = next_bin_digit(&cursor)) != -1;) {
		bits++;
		if (chr == 1)
			min_plen = bits;
	}

	if (bits == 0)
		panic("'%s' binary string is empty: %s", field->key, _src);

	if (*cursor == '/') {
		errno = 0;
		plen = strtoul(cursor + 1, &endptr, 10);
		if ((plen == ULONG_MAX && errno == ERANGE) || plen > SIZE_MAX)
			PREF_LEN_2BIG(field->key, _src);
		if (cursor + 1 == endptr)
			DEC_EINVAL(field->key, cursor + 1);
		if (plen < min_plen)
			PREF_TRUNC(field->key, _src);
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
				return;
			dst->buf[d] |= chr << (7 - b);
		}
}

static void
parse_bitstr(struct field *field, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	if (src->v.str[0] == '0' && src->v.str[1] == 'x') {
		parse_bitstr_hex(field, src->v.str, dst);
		return;
	}

	if (src->v.str[0] == '0' && src->v.str[1] == 'b') {
		parse_bitstr_bin(field, src->v.str, dst);
		return;
	}

	panic("'%s' has an unknown BIT_STRING format: %s",
	    field->key, src->v.str);
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

static void
parse_dec(char const *key, char const *src, INTEGER_t *dst)
{
	BIGNUM *bn;
	ASN1_INTEGER *asn1;
	unsigned char *der = NULL;
	int derlen;
	size_t i;

	bn = BN_new();
	if (!bn)
		enomem;
	if (BN_dec2bn(&bn, src) < 0)
		DEC_EINVAL(key, src);
	asn1 = BN_to_ASN1_INTEGER(bn, NULL);
	if (!asn1)
		enomem;
	derlen = i2d_ASN1_INTEGER(asn1, &der);
	if (derlen < 0)
		panic("i2d_ASN1_INTEGER(%s): %d", key, derlen);
	if (derlen > 127)
		/* Multi-byte length. Legal, but not considered below */
		panic("'%s' number is too big: %s", key, src);
	if (derlen < 2)
		panic("Bad DER header length: %d", derlen);
	if (der[0] != 2 || der[1] != (derlen - 2))
		panic("Bad DER header: %u %u", der[0], der[1]);

	dst->size = derlen - 2;
	dst->buf = pcalloc(dst->size, sizeof(uint8_t));
	for (i = 0; i < dst->size; i++)
		dst->buf[i] = der[i + 2];

	OPENSSL_free(der);
	ASN1_INTEGER_free(asn1);
	BN_free(bn);
}

static void
__parse_byte_array(struct field *field, char const *src,
    uint8_t **buf, size_t *size)
{
	BIT_STRING_t bs;
	INTEGER_t num;

	while (src[0] == ' ' || src[0] == '\t' || src[0] == '\n')
		src++;

	if (src[0] == '0' && src[1] == 'x') {
		memset(&bs, 0, sizeof(bs));
		parse_bitstr_hex(field, src, &bs);

	} else if (src[0] == '0' && src[1] == 'b') {
		memset(&bs, 0, sizeof(bs));
		parse_bitstr_bin(field, src, &bs);

	} else if (('0' <= src[0] && src[0] <= '9') || src[0] == '-') {
		memset(&num, 0, sizeof(num));
		parse_dec(field->key, src, &num);
		*buf = num.buf;
		*size = num.size;
		return;

	} else {
		DEC_EINVAL(field->key, src);
	}

	if ((bs.bits_unused & 7) != 0)
		panic("'%s' bit count is not a multiple of 8: %s",
		    field->key, src);

	*buf = bs.buf;
	*size = bs.size;
}

static void
parse_byte_array(struct field *field, struct kv_value *src,
    uint8_t **buf, size_t *size)
{
	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	__parse_byte_array(field, src->v.str, buf, size);
}

static void
parse_long_int(struct field *field, struct kv_value *src, long int *result)
{
	INTEGER_t integer;
	long int longint;

	parse_byte_array(field, src, &integer.buf, &integer.size);
	if (asn_INTEGER2long(&integer, &longint) < 0)
		DEC_EINVAL(field->key, src->v.str);

	*result = longint;
}

static void
parse_bool(struct field *field, struct kv_value *src, void *oid)
{
	BOOLEAN_t *boolean = oid;
	long int longint;

	if (src->type == VALT_STR) {
		if (strcmp(src->v.str, "true") == 0) {
			*boolean = 0xFF;
			return;
		}
		if (strcmp(src->v.str, "false") == 0) {
			*boolean = 0;
			return;
		}
	}

	parse_long_int(field, src, &longint);
	if (longint < INT_MIN || INT_MAX < longint)
		panic("Boolean out of range: %ld", longint);

	*boolean = (int)longint;
}

static void
print_bool(struct dynamic_string *dstr, void *val)
{
	BOOLEAN_t *boolean = val;
	if (boolean != NULL)
		dstr_append(dstr, (*boolean) ? "true" : "false");
}

static void
__parse_int(struct field *field, struct kv_value *src, INTEGER_t *dst)
{
	parse_byte_array(field, src, &dst->buf, &dst->size);
}

static void
parse_int(struct field *field, struct kv_value *src, void *dst)
{
	__parse_int(field, src, dst);
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

	/*
	 * TODO (fine) Naive; "0xFFFFFFFF" prints as "0x00FFFFFFFF".
	 * This is fine, but negative numbers are probably weirder.
	 */
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

static void
parse_oid_str(struct field *field, char const *src, OBJECT_IDENTIFIER_t *oid)
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
		return;
	}

	narcs = OBJECT_IDENTIFIER_parse_arcs(src, -1, NULL, 0, NULL);
	if (narcs < 0)
		BAD_OID(field->key, src);

	arcs = calloc(narcs, sizeof(asn_oid_arc_t));
	if (!arcs)
		enomem;

	narcs = OBJECT_IDENTIFIER_parse_arcs(src, -1, arcs, narcs, NULL);
	if (narcs < 0)
		BAD_OID(field->key, src);

	if (OBJECT_IDENTIFIER_set_arcs(oid, arcs, narcs) < 0)
		BAD_OID(field->key, src);
}

static void
parse_oid(struct field *field, struct kv_value *src, void *oid)
{
	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	parse_oid_str(field, src->v.str, oid);
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

static void
parse_8str(struct field *field, struct kv_value *src, void *dst)
{
	OCTET_STRING_t *result = dst;
	size_t size;

	switch (src->type) {
	case VALT_STR:
		result = dst;
		parse_byte_array(field, src, &result->buf, &size);

		result->size = size;
		field->children = NULL;
		return;

	case VALT_MAP:
		if (!field->address2)
			NEED_STRING(field->key);
		field->overridden = false;
		parse_obj(field, src, field->address2);
		return;

	default:
		NEED_STR_OR_MAP(field->key);
	}
}

static void
parse_utf8str(struct field *field, struct kv_value *src, void *dst)
{
	OCTET_STRING_t *str = dst;

	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	init_8str(str, src->v.str);
}

static void
print_utf8str(struct dynamic_string *dstr, void *val)
{
	OCTET_STRING_t *str = val;
	dstr_append(dstr, "%.*s", (int)str->size, (char *)str->buf);
}

static void
parse_ia5str(struct field *field, struct kv_value *src, void *dst)
{
	parse_utf8str(field, src, dst);
}

static void
print_ia5str(struct dynamic_string *dstr, void *val)
{
	print_utf8str(dstr, val);
}

static void
parse_anystr(struct field *field, struct kv_value *src, void *dst)
{
	ANY_t *anystr = dst;
	PrintableString_t ps;

	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	init_8str(&ps, src->v.str);
	der_encode_any(&asn_DEF_PrintableString, &ps, anystr);
}

static void
print_anystr(struct dynamic_string *dstr, void *val)
{
	ANY_t *anystr = val;

	if (anystr->size < 3 || anystr->buf[0] != 0x13) {
		dstr_append(dstr, "<Not a PrintableString>");
		return;
	}

	dstr_append(dstr, "%.*s",
	    (int)(anystr->size - 2),
	    (char *)(anystr->buf + 2));
}

static void
parse_cstr(struct field *field, struct kv_value *src, void *dst)
{
	char **cstr = dst;

	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	*cstr = src->v.str;
}

static void
print_cstr(struct dynamic_string *dstr, void *val)
{
	char **cstr = val;

	if (*cstr != NULL)
		dstr_append(dstr, "%s", *cstr);
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

static void
parse_any(struct field *field, struct kv_value *src, void *dst)
{
	ANY_t *any;
	size_t size;

	switch (src->type) {
	case VALT_STR:
		any = dst;
		parse_byte_array(field, src, &any->buf, &size);

		any->size = size;
		field->children = NULL;
		return;

	case VALT_MAP:
		if (!field->address2)
			NEED_STRING(field->key);
		field->overridden = false;
		parse_obj(field, src, field->address2);
		return;

	default:
		NEED_STR_OR_MAP(field->key);
	}
}

static void
print_any(struct dynamic_string *dstr, void *val)
{
	ANY_t *any = val;
	print_maybe_string(dstr, any->buf, any->size);
}

static void
parse_any_oid(struct field *field, struct kv_value *src, void *dst)
{
	OBJECT_IDENTIFIER_t oid = { 0 };
	ANY_t *any = dst;

	parse_oid(field, src, &oid);
	der_encode_any(&asn_DEF_OBJECT_IDENTIFIER, &oid, any);
}

static void
print_any_oid(struct dynamic_string *dstr, void *val)
{
	ANY_t *any = val;
	OBJECT_IDENTIFIER_t *oid = NULL;
	asn_dec_rval_t rval;

	rval = ber_decode_primitive(NULL, &asn_DEF_OBJECT_IDENTIFIER,
	    (void **)&oid, any->buf, any->size, 0);
	switch (rval.code) {
	case RC_OK:
		print_oid(dstr, oid);
		break;
	case RC_WMORE:
		pr_err("Error: Incomplete value");
		break;
	case RC_FAIL:
		pr_err("Error: Unparseable");
		break;
	}
}

static void
parse_rdnseq(struct field *field, struct kv_value *src, void *dst)
{
	struct kv_node *rdn_src;
	struct kv_node *atv_src;

	Name_t *name = dst;
	RelativeDistinguishedName_t *rdn_dst;
	AttributeTypeAndValue_t *atv_dst;

	struct field *rdnf;
	struct field *atvf;

	size_t r, a;

	if (src->type != VALT_SET)
		NEED_SET(field->key);

	name->present = Name_PR_rdnSequence;
	field->children = NULL;

	r = 0;
	STAILQ_FOREACH(rdn_src, &src->v.set, hook)
		r++;
	INIT_ASN1_ARRAY(&name->choice.rdnSequence.list, r, RelativeDistinguishedName_t);

	r = 0;
	STAILQ_FOREACH(rdn_src, &src->v.set, hook) {
		if (rdn_src->value.type != VALT_SET)
			NEED_SET(field->key);

		a = 0;
		STAILQ_FOREACH(atv_src, &rdn_src->value.v.set, hook)
			a++;

		rdn_dst = name->choice.rdnSequence.list.array[r];
		INIT_ASN1_ARRAY(&rdn_dst->list, a, AttributeTypeAndValue_t);
		rdnf = field_addn(field, r, NULL, rdn_dst, 0);

		a = 0;
		STAILQ_FOREACH(atv_src, &rdn_src->value.v.set, hook) {
			atv_dst = rdn_dst->list.array[a];

			atvf = field_addn(rdnf, a, &ft_obj, atv_dst, 0);
			field_add(atvf, "type", &ft_oid, &atv_dst->type, 0);
			field_add(atvf, "value", &ft_anystr, &atv_dst->value, 0);

			parse_obj(atvf, &atv_src->value, atv_dst);

			a++;
		}

		r++;
	}
}

static void
print_rdnseq(struct dynamic_string *dstr, void *arg)
{
	Name_t *name = arg;
	RDNSequence_t *seq;
	int s;
	RelativeDistinguishedName_t *rdn;
	int r;
	AttributeTypeAndValue_t *tv;

	seq = &name->choice.rdnSequence;
	dstr_append(dstr, "[ ");

	for (s = 0; s < seq->list.count; s++) {
		dstr_append(dstr, "[ ");

		rdn = seq->list.array[s];
		for (r = 0; r < rdn->list.count; r++) {
			tv = rdn->list.array[r];

			dstr_append(dstr, "{ \"");
			print_oid(dstr, &tv->type);
			dstr_append(dstr, "\": \"");
			print_anystr(dstr, &tv->value);
			dstr_append(dstr, "\" }");

			if (r != rdn->list.count - 1)
				dstr_append(dstr, ", ");
		}

		dstr_append(dstr, " ]");
		if (s != seq->list.count - 1)
			dstr_append(dstr, ", ");
	}

	dstr_append(dstr, " ]");
}

static void
parse_gname_type(struct field *field, struct kv_value *src, void *dst)
{
	GeneralName_PR present;
	struct field_type const *ft;
	GeneralName_t *gname = dst;

	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	if (strcmp(src->v.str, "rfc822Name") == 0) {
		present = GeneralName_PR_rfc822Name;
		ft = &ft_ia5str;
	} else if (strcmp(src->v.str, "dNSName") == 0) {
		present = GeneralName_PR_dNSName;
		ft = &ft_ia5str;
	} else if (strcmp(src->v.str, "uniformResourceIdentifier") == 0) {
		present = GeneralName_PR_uniformResourceIdentifier;
		ft = &ft_ia5str;
	} else if (strcmp(src->v.str, "iPAddress") == 0) {
		present = GeneralName_PR_iPAddress;
		ft = &ft_8str;
	} else if (strcmp(src->v.str, "registeredID") == 0) {
		present = GeneralName_PR_registeredID;
		ft = &ft_oid;
	} else {
		panic("'%s' has unknown GeneralName variant: %s",
		    field->key, src->v.str);
	}

	if (gname->present == present)
		return;

	gname->present = present;
	memset(&gname->choice, 0, sizeof(gname->choice));
	field_add(field->parent, "value", ft, &gname->choice, 0);
}

static void
print_gname_type(struct dynamic_string *dstr, void *arg)
{
	GeneralName_t *gname = arg;
	char const *value = NULL;

	switch (gname->present) {
	case GeneralName_PR_otherName:
		value = "otherName";
		break;
	case GeneralName_PR_rfc822Name:
		value = "rfc822Name";
		break;
	case GeneralName_PR_dNSName:
		value = "dNSName";
		break;
	case GeneralName_PR_x400Address:
		value = "x400Address";
		break;
	case GeneralName_PR_directoryName:
		value = "directoryName";
		break;
	case GeneralName_PR_ediPartyName:
		value = "ediPartyName";
		break;
	case GeneralName_PR_uniformResourceIdentifier:
		value = "uniformResourceIdentifier";
		break;
	case GeneralName_PR_iPAddress:
		value = "iPAddress";
		break;
	case GeneralName_PR_registeredID:
		value = "registeredID";
		break;
	case GeneralName_PR_NOTHING:
		break;
	}

	if (value)
		dstr_append(dstr, value);
}

static void
parse_time(struct field *field, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	init_time_str(dst, src->v.str);
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
	X509Time_t *time = val;

	switch (time->present) {
	case X509Time_PR_utcTime:
		print_utcTime(dstr, &time->choice.utcTime);
		break;
	case X509Time_PR_generalTime:
		print_gtime(dstr, &time->choice.generalTime);
		break;
	default:
		dstr_append(dstr, "<Printer not available for this data type>");
	}
}

static void
parse_gtime(struct field *field, struct kv_value *src, void *dst)
{
	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	init_gtime_str(dst, src->v.str);
}

static void
parse_filetype(struct field *field, struct kv_value *src_exts, void *_dst_exts)
{
	/* Actually done elsewhere */
}

static void
print_filetype(struct dynamic_string *dstr, void *val)
{
	enum file_type *ft = val;
	char const *str;

	switch (*ft) {
	case FT_TA:
	case FT_CER:	str = "cer";	break;
	case FT_CRL:	str = "crl";	break;
	case FT_MFT:	str = "mft";	break;
	case FT_ROA:	str = "roa";	break;
	case FT_ASA:	str = "asa";	break;
	default:	str = "?";	break;
	}

	dstr_append(dstr, "%s", str);
}

static sia_defaults
get_sia_defaults(struct field *field)
{
	/*
	 * Note: Hack (fallacious heuristic).
	 * We don't have a good way to find out the type of object we're
	 * building an SIA for.
	 * Relying on the topmost field name is sufficient but not future-proof.
	 */

	while (strcmp(field->parent->key, "obj") != 0)
		field = field->parent;

	if (strcmp(field->key, "tbsCertificate") == 0)
		return sia_ca_defaults;
	else if (strcmp(field->key, "content") == 0)
		return sia_ee_defaults;

	return sia_empty_defaults; /* CRL is known to fall through here */
}

static void
add_ext(char const *type, char const *name,
    struct extensions *exts, struct field *field)
{
	if (strncmp(type, "bc", 2) == 0)
		exts_add_bc(exts, name, field);
	else if (strncmp(type, "ski", 3) == 0)
		exts_add_ski(exts, name, field);
	else if (strncmp(type, "aki", 3) == 0)
		exts_add_aki(exts, name, field);
	else if (strncmp(type, "ku", 2) == 0)
		exts_add_ku(exts, name, field);
	else if (strncmp(type, "cdp", 3) == 0)
		exts_add_cdp(exts, name, field);
	else if (strncmp(type, "aia", 3) == 0)
		exts_add_aia(exts, name, field);
	else if (strncmp(type, "sia", 3) == 0)
		exts_add_sia(exts, name, field, get_sia_defaults(field));
	else if (strncmp(type, "cp", 2) == 0)
		exts_add_cp(exts, name, field);
	else if (strncmp(type, "ip", 2) == 0)
		exts_add_ip(exts, name, field);
	else if (strncmp(type, "as", 2) == 0)
		exts_add_as(exts, name, field);
	else if (strncmp(type, "cn", 2) == 0)
		exts_add_crln(exts, name, field);
	else
		panic("'%s' has an unknown extension type: %s",
		    field->key, type);
}

static void
parse_exts(struct field *field, struct kv_value *src_exts, void *_dst_exts)
{
	struct extensions *dst_exts;
	struct kv_node *node;

	switch (src_exts->type) {
	case VALT_SET:
		field->children = NULL;
		dst_exts = _dst_exts;
		STAILQ_INIT(dst_exts);

		STAILQ_FOREACH(node, &src_exts->v.set, hook) {
			if (node->value.type != VALT_STR)
				NEED_STRING(field->key);
			add_ext(node->value.v.str, node->value.v.str,
			    dst_exts, field);
		}

		return;

	case VALT_MAP:
		parse_obj(field, src_exts, _dst_exts);
		return;

	default:
		NEED_SET_OR_MAP(field->key);
	}
}

static void
print_exts(struct dynamic_string *dstr, void *_exts)
{
	struct extensions *exts = _exts;
	struct ext_list_node *ext;

	dstr_append(dstr, "[ ");
	STAILQ_FOREACH(ext, exts, hook) {
		dstr_append(dstr, "%s", ext->name);
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

static void
parse_ads(struct field *field, struct kv_value *src, void *dst)
{
	SubjectInfoAccessSyntax_t *sia = dst;
	struct kv_node *src_node;
	AccessDescription_t *dst_ad;
	struct field *adf;
	size_t a;

	if (src->type != VALT_SET)
		NEED_SET(field->key);

	field->children = NULL;

	a = 0;
	STAILQ_FOREACH(src_node, &src->v.set, hook)
		a++;
	INIT_ASN1_ARRAY(&sia->list, a, AccessDescription_t);

	a = 0;
	STAILQ_FOREACH(src_node, &src->v.set, hook) {
		dst_ad = sia->list.array[a];
		dst_ad->accessLocation.present = GeneralName_PR_uniformResourceIdentifier;

		adf = field_add_ad(field, a, dst_ad);
		parse_obj(adf, &src_node->value, dst_ad);

		a++;
	}
}

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

static void
parse_ip_node(struct field *field, char *str, struct ip_list_node **result)
{
	char *slash, *dash, *endptr;
	unsigned long plen;
	struct ip_list_node *ipnode;
	unsigned int index1;

	slash = strchr(str, '/');
	if (slash != NULL)
		*slash = '\0';

	ipnode = pzalloc(sizeof(struct ip_list_node));
	ipnode->af = (strchr(str, ':') != NULL) ? AF_INET6 : AF_INET;

	if (inet_pton(ipnode->af, str, ipnode->bits) < 1) {
		if (slash != NULL)
			*slash = '/';
		panic("'%s' has an unparseable IP address: %s", field->key, str);
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
		return;
	}

	*slash = '/';

	dash = NULL;
	errno = 0;
	plen = strtoul(slash + 1, &dash, 10);
	if ((plen == ULONG_MAX && errno == ERANGE) || plen > UINT_MAX)
		PREF_LEN_2BIG(field->key, str);
	if (slash + 1 == dash)
		DEC_EINVAL(field->key, slash + 1);
	index1 = find_last_1_index(ipnode->bits);
	if (index1 != UINT_MAX && index1 >= plen)
		PREF_TRUNC(field->key, str);

	ipnode->plen = plen;
	if ((*dash) != '-') {
		*result = ipnode;
		return;
	}

	errno = 0;
	plen = strtoul(dash + 1, &endptr, 10);
	if ((plen == ULONG_MAX && errno == ERANGE) || plen > UINT_MAX)
		PREF_LEN_2BIG(field->key, str);
	if (dash + 1 == endptr)
		DEC_EINVAL(field->key, dash + 1);

	ipnode->has_maxlen = true;
	ipnode->maxlen = plen;
	*result = ipnode;
}

struct parsed_ips {
	struct ip_list v4list;
	unsigned int v4n;

	struct ip_list v6list;
	unsigned int v6n;
};

static void
kvs2ips(struct field *field, struct kv_set *kvs, struct parsed_ips *ips)
{
	struct kv_node *node;
	struct ip_list_node *ipnode;

	STAILQ_INIT(&ips->v4list);
	ips->v4n = 0;
	STAILQ_INIT(&ips->v6list);
	ips->v6n = 0;

	STAILQ_FOREACH(node, kvs, hook) {
		if (node->value.type != VALT_STR)
			NEED_STRING(field->key);
		parse_ip_node(field, node->value.v.str, &ipnode);

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
			panic("'%s' has an unknown AF: %u\n",
			    field->key, ipnode->af);
		}
	}
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

static void
parse_ips_roa(struct field *field, struct kv_value *src, void *arg)
{
	struct RouteOriginAttestation__ipAddrBlocks *dst = arg;
	struct parsed_ips ips;

	if (src->type != VALT_SET)
		NEED_SET(field->key);
	kvs2ips(field, &src->v.set, &ips);

	INIT_ASN1_ARRAY(&dst->list, !!ips.v4n + !!ips.v6n, struct ROAIPAddressFamily);
	if (ips.v4n)
		convert_ips(dst->list.array[0], 1, &ips.v4list, ips.v4n);
	if (ips.v6n)
		convert_ips(dst->list.array[ips.v4n ? 1 : 0], 2, &ips.v6list, ips.v6n);
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

static void
parse_ips_str(struct field *field, struct kv_value *src, IPAddrBlocks_t *dst)
{
	if (strcmp("inherit", src->v.str) != 0)
		BAD_IPS(field->key);

	INIT_ASN1_ARRAY(&dst->list, 2, struct IPAddressFamily);

	init_af(&dst->list.array[0]->addressFamily, 1);
	dst->list.array[0]->ipAddressChoice.present = IPAddressChoice_PR_inherit;
	init_af(&dst->list.array[1]->addressFamily, 2);
	dst->list.array[1]->ipAddressChoice.present = IPAddressChoice_PR_inherit;
}

static void
parse_ips_set(struct field *field, struct kv_value *src, IPAddrBlocks_t *dst)
{
	struct parsed_ips ips;

	kvs2ips(field, &src->v.set, &ips);

	INIT_ASN1_ARRAY(&dst->list, !!ips.v4n + !!ips.v6n, struct IPAddressFamily);
	if (ips.v4n)
		convert_ips_cer(dst->list.array[0], 1, &ips.v4list, ips.v4n);
	if (ips.v6n)
		convert_ips_cer(dst->list.array[ips.v4n ? 1 : 0], 2, &ips.v6list, ips.v6n);
}

static void
parse_ips_cer(struct field *field, struct kv_value *src, void *arg)
{
	switch (src->type) {
	case VALT_STR:
		parse_ips_str(field, src, arg);
		return;
	case VALT_SET:
		parse_ips_set(field, src, arg);
		return;
	case VALT_MAP:
		break;
	}

	BAD_IPS(field->key);
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

static void
parse_asns_str(struct field *field, struct kv_value *src,
    ASIdentifierChoice_t *dst)
{
	if (strcmp("inherit", src->v.str) != 0)
		BAD_ASN(field->key);

	dst->present = ASIdentifierChoice_PR_inherit;
}

static void
parse_as_range(struct field *field, struct kv_value *src, ASRange_t *dst)
{
	char *str;
	char *dash;

	if (src->type != VALT_STR)
		NEED_STRING(field->key);

	str = pstrdup(src->v.str);

	dash = strchr(str, '-');
	if (!dash)
		panic("'%s' range is missing a dash: %s", field->key, src->v.str);
	*dash = 0;

	__parse_byte_array(field, str, &dst->min.buf, &dst->min.size);
	__parse_byte_array(field, dash + 1, &dst->max.buf, &dst->max.size);

	free(str);

}

static void
parse_asns_set(struct field *field, struct kv_value *src,
    ASIdentifierChoice_t *aic)
{
	struct kv_node *node;
	ASIdOrRange_t *aor;
	int n;

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		n++;

	aic->present = ASIdentifierChoice_PR_asIdsOrRanges;
	INIT_ASN1_ARRAY(&aic->choice.asIdsOrRanges.list, n, struct ASIdOrRange);

	n = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		if (node->value.type != VALT_STR)
			NEED_STRING(field->key);

		aor = aic->choice.asIdsOrRanges.list.array[n++];
		if (strchr(node->value.v.str, '-') != NULL) {
			aor->present = ASIdOrRange_PR_range;
			parse_as_range(field, &node->value, &aor->choice.range);
		} else {
			aor->present = ASIdOrRange_PR_id;
			__parse_int(field, &node->value, &aor->choice.id);
		}
	}
}

static void
parse_asns(struct field *field, struct kv_value *src, void *arg)
{
	switch (src->type) {
	case VALT_STR:
		parse_asns_str(field, src, arg);
		return;
	case VALT_SET:
		parse_asns_set(field, src, arg);
		return;
	case VALT_MAP:
		break;
	}

	BAD_ASN(field->key);
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

static void
parse_revoked_list(struct field *field, struct kv_value *src, void *arg)
{
	struct TBSCertList__revokedCertificates *rcs;
	struct kv_node *node;
	int n;

	if (src->type != VALT_SET)
		NEED_SET(field->key);

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
		__parse_int(
		    field,
		    &node->value,
		    &rcs->list.array[n]->userCertificate
		);
		n++;
	}
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

static void
parse_filelist_str(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	long int count;

	parse_long_int(rootf, src, &count);
	if (count < 0 || SIZE_MAX < count)
		panic("filelist length out of range: %ld", count);

	INIT_ASN1_ARRAY(&filelist->list, count, FileAndHash_t);
	add_filelist_fields(rootf, filelist, false, false);
}

static void
parse_filelist_set(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	struct kv_node *node;
	size_t f;

	f = 0;
	STAILQ_FOREACH(node, &src->v.set, hook) {
		if (node->value.type != VALT_STR)
			panic("%s: fileList entry is not a string", rootf->key);
		f++;
	}

	INIT_ASN1_ARRAY(&filelist->list, f, FileAndHash_t);
	f = 0;
	STAILQ_FOREACH(node, &src->v.set, hook)
		init_8str(&filelist->list.array[f++]->file, node->value.v.str);

	add_filelist_fields(rootf, filelist, true, false);
}

static void
parse_filelist_map(struct field *rootf, struct kv_value *src,
    struct Manifest__fileList *filelist)
{
	struct keyval *kv;
	FileAndHash_t *fah;
	int f;

	f = 0;
	STAILQ_FOREACH(kv, &src->v.map, hook) {
		if (kv->value.type != VALT_STR)
			panic("%s: fileList entry is not a string", rootf->key);
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
}

static void
parse_filelist(struct field *rootf, struct kv_value *src, void *arg)
{
	rootf->children = NULL;

	switch (src->type) {
	case VALT_STR:	parse_filelist_str(rootf, src, arg);	break;
	case VALT_SET:	parse_filelist_set(rootf, src, arg);	break;
	case VALT_MAP:	parse_filelist_map(rootf, src, arg);	break;
	}
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
		print_utf8str(dstr, &fah->file);
		dstr_append(dstr, "=");
		print_bitstr(dstr, &fah->hash);

		print_array_separator(dstr, f, filelist->list.count);
	}

	dstr_append(dstr, "}");
}

static void
parse_providers(struct field *rootf, struct kv_value *src, void *arg)
{
	ProviderASSet_t *providers = arg;
	struct kv_node *kv;
	int p;

	if (src->type != VALT_SET)
		panic("%s: Providers list is not an array.", rootf->key);

	p = 0;
	STAILQ_FOREACH(kv, &src->v.set, hook)
		p++;

	INIT_ASN1_ARRAY(&providers->list, p, ASId_t);
	p = 0;
	STAILQ_FOREACH(kv, &src->v.set, hook) {
		__parse_int(rootf, &kv->value, providers->list.array[p]);

//		field_addn(rootf, p, &ft_int, providers->list.array[p],
//		    sizeof(ASId_t));

		p++;
	}
}

static void
print_providers(struct dynamic_string *dstr, void *arg)
{
	ProviderASSet_t *providers = arg;
	int a;

	dstr_append(dstr, "[ ");
	for (a = 0; a < providers->list.count; a++) {
		print_int(dstr, providers->list.array[a]);
		if (a != providers->list.count - 1)
			dstr_append(dstr, ", ");
	}
	dstr_append(dstr, " ]");
}

static void
parse_files(struct field *rootf, struct kv_value *src, void *dst)
{
	struct kv_node *node;
	struct rrdp_file *file;
	struct rrdp_files *files = dst;

	if (src->type != VALT_SET)
		NEED_SET(rootf->key);

	STAILQ_FOREACH(node, &src->v.set, hook) {
		if (node->value.type != VALT_STR)
			NEED_STRING(rootf->key);

		pr_trace("Adding %s to Notification", node->value.v.str);
		file = pzalloc(sizeof(struct rrdp_file));
		file->name = node->value.v.str;
		STAILQ_INSERT_TAIL(files, file, hook);
	}
}

static void
print_files(struct dynamic_string *dstr, void *arg)
{
	struct rrdp_files *files = arg;
	struct rrdp_file *file;

	dstr_append(dstr, "[ ");
	STAILQ_FOREACH(file, files, hook) {
		dstr_append(dstr, "%s", file->name);
		if (STAILQ_NEXT(file, hook) != NULL)
			dstr_append(dstr, ", ");
	}
	dstr_append(dstr, " ]");
}

const struct field_type ft_obj = { "Object", parse_obj, NULL };
const struct field_type ft_bool = { "BOOLEAN", parse_bool, print_bool };
const struct field_type ft_int = { "INTEGER", parse_int, print_int };
const struct field_type ft_oid = { "OBJECT IDENTIFIER", parse_oid, print_oid };
const struct field_type ft_8str = { "OCTET STRING", parse_8str, print_8str };
const struct field_type ft_utf8str = { "UTF8String", parse_utf8str, print_utf8str };
const struct field_type ft_ia5str = { "IA5String", parse_ia5str, print_ia5str };
const struct field_type ft_anystr = { "PrintableString in ANY", parse_anystr, print_anystr };
const struct field_type ft_cstr = { "C String", parse_cstr, print_cstr };
const struct field_type ft_any = { "ANY", parse_any, print_any };
const struct field_type ft_any_oid = { "ANY-OID", parse_any_oid, print_any_oid };
const struct field_type ft_bitstr = { "BIT STRING", parse_bitstr, print_bitstr };
const struct field_type ft_rdnseq = { "RDN Sequence", parse_rdnseq, print_rdnseq };
const struct field_type ft_gname_type = { "GeneralName type", parse_gname_type, print_gname_type };
const struct field_type ft_time = { "Time", parse_time, print_time };
const struct field_type ft_gtime = { "GeneralizedTime", parse_gtime, print_gtime };
const struct field_type ft_filetype = { "File Type", parse_filetype, print_filetype };
const struct field_type ft_exts = { "Extensions", parse_exts, print_exts };
const struct field_type ft_ads = { "Access Descriptions", parse_ads, NULL };
const struct field_type ft_ip_roa = { "IP Resources (ROA)", parse_ips_roa, print_roa_ips };
const struct field_type ft_ip_cer = { "IP Resources (Certificate)", parse_ips_cer, print_cer_ips };
const struct field_type ft_as_cer = { "AS Resources", parse_asns, print_asns };
const struct field_type ft_revoked = { "Revoked Certificates", parse_revoked_list, print_revokeds };
const struct field_type ft_filelist = { "File List", parse_filelist, print_filelist };
const struct field_type ft_providers = { "ASPA Providers", parse_providers, print_providers };
const struct field_type ft_files = { "Snapshot Files", parse_files, print_files };

struct field *
__field_add(struct field *parent, char const *name)
{
	struct field *old, *new;
	size_t namelen;

	new = pzalloc(sizeof(struct field));
	new->key = name;
	new->parent = parent;

	namelen = strlen(name);

	HASH_FIND(hh, parent->children, name, namelen, old);
	if (old)
		HASH_DEL(parent->children, old);
	HASH_ADD_KEYPTR(hh, parent->children, name, namelen, new);

	return new;
}

#define n2str(n, str) psnprintf(str, 20, "%zu", n)

struct field *
field_addn(struct field *parent, size_t n,
    struct field_type const *type, void *address, size_t size)
{
	char buf[20];
	n2str(n, buf);
	return field_add(parent, pstrdup(buf), type, address, size);
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
field_add_name(struct field *parent, char const *key, Name_t *name)
{
	struct RelativeDistinguishedName *rdn;
	struct AttributeTypeAndValue *atv;
	struct field *rootf, *rdnsf;
	struct field *rdnf, *atvf;
	int r, a;

	rootf = field_add(parent, key, &ft_obj, name, 0);
	rdnsf = field_add(rootf, "rdnSequence", &ft_rdnseq, name, 0);

	for (r = 0; r < name->choice.rdnSequence.list.count; r++) {
		rdn = name->choice.rdnSequence.list.array[r];
		rdnf = field_addn(rdnsf, 0, NULL, NULL, 0);

		for (a = 0; a < rdn->list.count; a++) {
			atv = rdn->list.array[a];
			atvf = field_addn(rdnf, 0, &ft_obj, atv, 0);

			field_add(atvf, "type", &ft_oid, &atv->type, 0);
			field_add(atvf, "value", &ft_anystr, &atv->value, 0);
		}
	}

	return rootf;
}

struct field *
field_add_gname(struct field *parent, char const *key, GeneralName_t *gn)
{
	struct field *gnf;
	struct field_type const *value_ft = NULL;

	switch (gn->present) {
	case GeneralName_PR_NOTHING:
		break;
	case GeneralName_PR_rfc822Name:
	case GeneralName_PR_dNSName:
	case GeneralName_PR_uniformResourceIdentifier:
		value_ft = &ft_ia5str;
		break;
	case GeneralName_PR_iPAddress:
		value_ft = &ft_8str;
		break;
	case GeneralName_PR_registeredID:
		value_ft = &ft_oid;
		break;
	case GeneralName_PR_otherName:
	case GeneralName_PR_x400Address:
	case GeneralName_PR_directoryName:
	case GeneralName_PR_ediPartyName:
		// TODO Missing variants
		panic("Not implemented yet: General variant %d", gn->present);
	}

	gnf = field_add(parent, key, &ft_obj, gn, 0);
	field_add(gnf, "type", &ft_gname_type, gn, 0);
	if (value_ft)
		field_add(gnf, "value", value_ft, &gn->choice, 0);

	return gnf;
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
field_add_ad(struct field *parent, size_t adn, AccessDescription_t *ad)
{
	struct field *adf;

	adf = field_addn(parent, adn, &ft_obj, ad, 0);
	field_add(adf, "accessMethod", &ft_oid, &ad->accessMethod, 0);
	field_add_gname(adf, "accessLocation", &ad->accessLocation);

	return adf;
}

struct field *
__fields_find(struct field *root, char const *key, bool prepare)
{
	struct field *parent, *child;
	char const *dot;
	size_t keylen;

	if (root == NULL)
		return NULL;
	if (key == NULL)
		return root;
	parent = root;

	do {
		if (prepare && (parent->prepare != NULL))
			parent->prepare(parent->prepare_arg);

		dot = strchr(key, '.');
		if (!dot) {
			keylen = strlen(key);
			HASH_FIND(hh, parent->children, key, keylen, child);
			if (child && prepare && (child->prepare != NULL))
				child->prepare(child->prepare_arg);
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

static bool
is_null(struct kv_value *value)
{
	return (value->type == VALT_STR)
	    ? (strcmp(value->v.str, "NULL") == 0)
	    : false;
}

void
fields_apply_keyvals(struct field *root, struct keyvals *kvs)
{
	struct keyval *kv;
	struct field *field;
	unsigned char **value;

	STAILQ_FOREACH(kv, kvs, hook) {
		pr_trace("keyval: %s", kv->key);

		field = __fields_find(root, kv->key, true);
		if (!field)
			panic("Key '%s' is unknown.", kv->key);
		if (!field->type || !field->type->parser)
			panic("I don't have a parser for '%s'", kv->key);

		field->overridden = true;

		value = field->address;
		if (is_pointer(field)) {
			if (is_null(&kv->value)) {
				*value = NULL;
				continue;
			}
			if (*value == NULL)
				*value = pzalloc(field->size);
			field->type->parser(field, &kv->value, *value);
		} else {
			field->type->parser(field, &kv->value, value);
		}
	}
}

static char *
field2str(struct field const *field)
{
	unsigned char **address;
	struct dynamic_string dstr = { 0 };

	address = field->address;
	if (is_pointer(field)) {
		if (*address != NULL)
			field->type->print(&dstr, *address);
	} else {
		field->type->print(&dstr, address);
	}

	return dstr.buf;
}

static void
__fields_print(struct field const *field, char *key, size_t key_offset,
    bool is_null)
{
	char *printable;
	struct field *child, *tmp;

	strcpy(key + key_offset, field->key);

	if (field->cond && !field->cond(field->cond_arg))
		is_null = true;

	if (field->type && field->type->print) {
		if (is_null) {
			printf("%s = NULL\n", key);
		} else {
			printable = field2str(field);
			printf("%s = %s\n", key, printable);
			free(printable);
		}
	}

	key_offset += strlen(field->key);
	key[key_offset] = '.';
	HASH_ITER(hh, field->children, child, tmp)
		__fields_print(child, key, key_offset + 1, is_null);
}

void
fields_print_md(struct field const *root)
{
	struct field const *child, *tmp;
	char key[FIELD_MAXLEN];

	printf("```\n");
	HASH_ITER(hh, root->children, child, tmp)
		__fields_print(child, key, 0, false);
	printf("```\n");
}

static void
__fields_print_csv(char const *name, struct field const *field,
    char *key, size_t key_offset, bool is_null)
{
	char *printable;
	struct field *child, *tmp;

	strcpy(key + key_offset, field->key);

	if (field->cond && !field->cond(field->cond_arg))
		is_null = true;

	if (field->type && field->type->print) {
		csv_print(name, ',');
		csv_print(key, ',');
		csv_print(field->type->name, ',');

		if (is_null) {
			csv_print("NULL", '\n');
		} else {
			printable = field2str(field);
			csv_print(printable, '\n');
			free(printable);
		}
	}

	key_offset += strlen(field->key);
	key[key_offset] = '.';
	HASH_ITER(hh, field->children, child, tmp)
		__fields_print_csv(name, child, key, key_offset + 1, is_null);
}

void
fields_print_csv(struct field const *fields, char const *name)
{
	struct field const *field, *tmp;
	char key[FIELD_MAXLEN];

	HASH_ITER(hh, fields->children, field, tmp)
		__fields_print_csv(name, field, key, 0, false);
}
