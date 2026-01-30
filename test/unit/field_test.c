#include "../src/field.c"

#include <check.h>

#include "../src/global.h"

/* Mocks */

char const *
cer_rpkiManifest(struct rpki_certificate *cer)
{
	ck_abort_msg("%s() called!", __func__);
}

/* Tests */

#define ck_hexstr(input, bytes, unused) do {				\
		memset(&bs, 0, sizeof(bs));				\
		ck_assert_pstr_eq(NULL, parse_bitstr_hex(input, &bs));	\
		ck_assert_uint_eq(bytes, bs.size);			\
		ck_assert_int_eq(unused, bs.bits_unused);		\
	} while (0);

#define ck_hexstr_fail(input, error) do {				\
		memset(&bs, 0, sizeof(bs));				\
		ck_assert_pstr_eq(error, parse_bitstr_hex(input, &bs));	\
	} while (0);

START_TEST(check_parse_bitstr_hex)
{
	BIT_STRING_t bs;
	size_t i;

	printf("===== 1 byte ======\n");
	ck_hexstr("0xFF", 1, 0);
	ck_assert_int_eq(0xFF, bs.buf[0]);

	printf("===== 2 bytes ======\n");
	ck_hexstr("0xABFF", 2, 0);
	ck_assert_int_eq(0xAB, bs.buf[0]);
	ck_assert_int_eq(0xFF, bs.buf[1]);

	printf("===== 2 bytes, separator included ======\n");
	ck_hexstr("0xAB:FF", 2, 0);
	ck_assert_int_eq(0xAB, bs.buf[0]);
	ck_assert_int_eq(0xFF, bs.buf[1]);

	printf("===== 2 bytes, zero lead ======\n");
	ck_hexstr("0x0123", 2, 0);
	ck_assert_int_eq(0x01, bs.buf[0]);
	ck_assert_int_eq(0x23, bs.buf[1]);

	printf("===== Left Padding ======\n");
	ck_hexstr("0x000123", 3, 0);
	ck_assert_int_eq(0x00, bs.buf[0]);
	ck_assert_int_eq(0x01, bs.buf[1]);
	ck_assert_int_eq(0x23, bs.buf[2]);

	printf("===== Large number, even digits ======\n");
	ck_hexstr("0x000102030405060708090A0B0C0D0E0F"
		    "101112131415161718191A1B1C1D1E1F", 32, 0);
	for (i = 0; i < 32; i++)
		ck_assert_int_eq(i, bs.buf[i]);

	printf("===== Large number, odd digits ======\n");
	ck_hexstr("0x0102030405060708090A0B0C0D0E0F"
		  "101112131415161718191A1B1C1D1E1F"
		  "202122232425262728292A2B2C2D2E2F"
		  "303132333435363738393A3B3C3D3E3F", 63, 0);
	for (i = 0; i < 63; i++)
		ck_assert_int_eq(i + 1, bs.buf[i]);

	printf("===== Messy separators ======\n");
	ck_hexstr("0x 0102 0304  0506:07::0_:_80	\n\t9", 9, 0);
	for (i = 0; i < 9; i++)
		ck_assert_int_eq(i + 1, bs.buf[i]);

	printf("===== Outer separators ======\n");
	ck_hexstr("0x:0102:", 2, 0);
	ck_assert_int_eq(0x01, bs.buf[0]);
	ck_assert_int_eq(0x02, bs.buf[1]);

	printf("===== Simple prefix ======\n");
	ck_hexstr("0x20010db8/32", 4, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0x01, bs.buf[1]);
	ck_assert_int_eq(0x0d, bs.buf[2]);
	ck_assert_int_eq(0xb8, bs.buf[3]);

	printf("===== Prefix fill ======\n");
	ck_hexstr("0x20010db8/48", 6, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0x01, bs.buf[1]);
	ck_assert_int_eq(0x0d, bs.buf[2]);
	ck_assert_int_eq(0xb8, bs.buf[3]);
	ck_assert_int_eq(0x00, bs.buf[4]);
	ck_assert_int_eq(0x00, bs.buf[5]);

	printf("===== Prefix truncate ======\n");
	ck_hexstr_fail("0x20010db8/16", PREF_TRUNC);

	printf("===== Bits and prefix lengths =====\n");
	ck_hexstr("0x:20FF/16", 2, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xFF, bs.buf[1]);

	ck_hexstr_fail("0x20FF/15", PREF_TRUNC);
	ck_hexstr("0x2:0FE/15", 2, 1);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xFE, bs.buf[1]);

	ck_hexstr_fail("0x20FE/14", PREF_TRUNC);
	ck_hexstr("0x20:FC/14", 2, 2);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xFC, bs.buf[1]);

	ck_hexstr_fail("0x20FC/13", PREF_TRUNC);
	ck_hexstr("0x20F:8/13", 2, 3);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xF8, bs.buf[1]);

	ck_hexstr_fail("0x20F8/12", PREF_TRUNC);
	ck_hexstr("0x20F0:/12", 2, 4);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xF0, bs.buf[1]);

	ck_hexstr_fail("0x20F0/11", PREF_TRUNC);
	ck_hexstr("0x20::E0/11", 2, 5);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xE0, bs.buf[1]);

	ck_hexstr_fail("0x20E0/10", PREF_TRUNC);
	ck_hexstr("0x2_0C_0/10", 2, 6);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0xC0, bs.buf[1]);

	ck_hexstr_fail("0x20C0/9", PREF_TRUNC);
	ck_hexstr("0x20  80/9", 2, 7);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_assert_int_eq(0x80, bs.buf[1]);

	ck_hexstr_fail("0x2080/8", PREF_TRUNC);
	ck_hexstr("0x2000/8", 1, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_hexstr("0x20\t/8", 1, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);
	ck_hexstr("0x200000/8", 1, 0);
	ck_assert_int_eq(0x20, bs.buf[0]);

	ck_hexstr_fail("0x", HEX_EMPTY);
}
END_TEST

#define ck_binstr(input, bytes, unused) do {				\
		memset(&bs, 0, sizeof(bs));				\
		ck_assert_pstr_eq(NULL, parse_bitstr_bin(input, &bs));	\
		ck_assert_uint_eq(bytes, bs.size);			\
		ck_assert_int_eq(unused, bs.bits_unused);		\
	} while (0);

#define ck_binstr_fail(input, error) do {				\
		memset(&bs, 0, sizeof(bs));				\
		ck_assert_pstr_eq(error, parse_bitstr_bin(input, &bs));	\
	} while (0);

START_TEST(check_parse_bitstr_bin)
{
	BIT_STRING_t bs;
	size_t i;

	printf("===== 1 byte, 8 bits ======\n");
	ck_binstr("0b10110001", 1, 0);
	ck_assert_int_eq(bs.buf[0], 0xB1);

	printf("===== 1 byte, 7 bits ======\n");
	ck_binstr("0b1011001", 1, 1);
	ck_assert_int_eq(bs.buf[0], 0xB2);

	printf("===== 1 byte, 7 bits, separator ======\n");
	ck_binstr("0b1011_001", 1, 1);
	ck_assert_int_eq(bs.buf[0], 0xB2);

	printf("===== 1 byte, 4 bits ======\n");
	ck_binstr("0b1100", 1, 4);
	ck_assert_int_eq(bs.buf[0], 0xC0);

	printf("===== 1 byte, 1 bit ======\n");
	ck_binstr("0b1", 1, 7);
	ck_assert_int_eq(bs.buf[0], 0x80);

	printf("===== 2 bytes, 16 bits ======\n");
	ck_binstr("0b1010010101000010", 2, 0);
	ck_assert_int_eq(bs.buf[0], 0xA5);
	ck_assert_int_eq(bs.buf[1], 0x42);

	printf("===== 2 bytes, 14 bits ======\n");
	ck_binstr("0b10100101010001", 2, 2);
	ck_assert_int_eq(bs.buf[0], 0xA5);
	ck_assert_int_eq(bs.buf[1], 0x44);

	printf("===== 4 bytes, 25 bits ======\n");
	ck_binstr("0b1001000110100010101100111", 4, 7);
	ck_assert_int_eq(bs.buf[0], 0x91);
	ck_assert_int_eq(bs.buf[1], 0xA2);
	ck_assert_int_eq(bs.buf[2], 0xB3);
	ck_assert_int_eq(bs.buf[3], 0x80);

	printf("===== Large number ======\n");
	ck_binstr("0b"	"00000000" "00000001" "00000010" "00000011"
			"00000100" "00000101" "00000110" "00000111"
			"00001000" "00001001" "00001010" "00001011"
			"00001100" "00001101" "00001110" "00001111"
			"00010000" "00010001" "00010010" "00010011"
			"00010100" "00010101" "00010110" "00010111"
			"00011000" "00011001" "00011010" "00011011"
			"00011100" "00011101" "00011110" "00011111"
			"00100000" "00100001" "00100010" "00100011"
			"00100100" "00100101" "00100110" "00100111"
			"00101000" "00101001" "00101010" "00101011"
			"00101100" "00101101" "00101110" "00101111"
			"00110000" "00110001" "00110010" "00110011"
			"00110100" "00110101" "00110110" "00110111"
			"00111000" "00111001" "00111010" "00111011"
			"00111100" "00111101" "00111110" "00111111"
			"01000000" "01000001" "01000010" "01000011", 68, 0);
	for (i = 0; i < 68; i++)
		ck_assert_int_eq(i, bs.buf[i]);

	printf("===== /8 ======\n");
	ck_binstr("0b10010110/8", 1, 0);
	ck_assert_int_eq(150, bs.buf[0]);

	printf("===== /7 ======\n");
	ck_binstr("0b1001011/7", 1, 1);
	ck_assert_int_eq(150, bs.buf[0]);

	printf("===== /1 ======\n");
	ck_binstr("0b1/1", 1, 7);
	ck_assert_int_eq(128, bs.buf[0]);

	printf("===== /16 ======\n");
	ck_binstr("0b1001011010000001/16", 2, 0);
	ck_assert_int_eq(150, bs.buf[0]);
	ck_assert_int_eq(129, bs.buf[1]);

	printf("===== /15 ======\n");
	ck_binstr("0b100101101000000/15", 2, 1);
	ck_assert_int_eq(150, bs.buf[0]);
	ck_assert_int_eq(128, bs.buf[1]);

	printf("===== /17 ======\n");
	ck_binstr("0b10010110100000011/17", 3, 7);
	ck_assert_int_eq(150, bs.buf[0]);
	ck_assert_int_eq(129, bs.buf[1]);
	ck_assert_int_eq(128, bs.buf[2]);

	printf("===== /15, fill all zeroes ======\n");
	ck_binstr("0b100101101/15", 2, 1);
	ck_assert_int_eq(150, bs.buf[0]);
	ck_assert_int_eq(128, bs.buf[1]);

	printf("===== /15, fill some zeroes ======\n");
	ck_binstr("0b10010110100/15", 2, 1);
	ck_assert_int_eq(150, bs.buf[0]);
	ck_assert_int_eq(128, bs.buf[1]);

	printf("===== Only zeroes after the prefix length ======\n");
	ck_binstr("0b10/1", 1, 7);
	ck_assert_int_eq(0x80, bs.buf[0]);

	printf("===== Ones after the prefix length ======\n");
	ck_binstr_fail("0b11/1", PREF_TRUNC);
}
END_TEST

START_TEST(check_parse_int_dec)
{
	struct kv_value kv;
	INTEGER_t num;

	kv.type = VALT_STR;

	memset(&num, 0, sizeof(num));
	kv.v.str = "123";
	ck_assert_pstr_eq(NULL, parse_int(NULL, &kv, &num));
	ck_assert_int_eq(num.size, 1);
	ck_assert_int_eq(num.buf[0], 0x7B);

	memset(&num, 0, sizeof(num));
	kv.v.str = "1234567890";
	ck_assert_pstr_eq(NULL, parse_int(NULL, &kv, &num));
	ck_assert_int_eq(num.size, 4);
	ck_assert_int_eq(num.buf[0], 0x49);
	ck_assert_int_eq(num.buf[1], 0x96);
	ck_assert_int_eq(num.buf[2], 0x02);
	ck_assert_int_eq(num.buf[3], 0xD2);

	/* Meh */
}
END_TEST

START_TEST(check_tutorial_examples)
{
	struct kv_value kv;
	INTEGER_t num;
	struct field dummy = { 0};
	OCTET_STRING_t os;
	BIT_STRING_t bs;
	ANY_t any;

	asn_enc_rval_t rval;
	unsigned char buf[64] = { 0 };
	long int i;

	kv.type = VALT_STR;

	/*
	 * Because of their numeric natures, `INTEGER`, `OCTET STRING`s,
	 * `BIT STRING`s and `ANY` share the same parser:
	 */

	memset(&num, 0, sizeof(num));
	kv.v.str = "4660";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 2);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x1234";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 2);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);

	memset(&num, 0, sizeof(num));
	kv.v.str = "0b0001001000110100";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 2);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);

	memset(&os, 0, sizeof(os));
	kv.v.str = "4660";
	ck_assert_pstr_eq(NULL, parse_8str(&dummy, &kv, &os));
	ck_assert_int_eq(os.size, 2);
	ck_assert_int_eq(os.buf[0], 0x12);
	ck_assert_int_eq(os.buf[1], 0x34);

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0x1234";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 2);
	ck_assert_int_eq(bs.buf[0], 0x12);
	ck_assert_int_eq(bs.buf[1], 0x34);
	ck_assert_int_eq(bs.bits_unused, 0);

	memset(&any, 0, sizeof(any));
	kv.v.str = "0b0001001000110100";
	ck_assert_pstr_eq(NULL, parse_any(&dummy, &kv, &any));
	ck_assert_int_eq(any.size, 2);
	ck_assert_int_eq(any.buf[0], 0x12);
	ck_assert_int_eq(any.buf[1], 0x34);

	/*
	 * Think of hexadecimals and binaries as byte arrays. You get one byte
	 * every two hexadecimal digits or eight binary ones:
	 */

	memset(&any, 0, sizeof(any));
	kv.v.str = "0x123456";
	ck_assert_pstr_eq(NULL, parse_any(&dummy, &kv, &any));
	ck_assert_int_eq(any.size, 3);
	ck_assert_int_eq(any.buf[0], 0x12);
	ck_assert_int_eq(any.buf[1], 0x34);
	ck_assert_int_eq(any.buf[2], 0x56);

	memset(&any, 0, sizeof(any));
	kv.v.str = "0b000100100011010001010110";
	ck_assert_pstr_eq(NULL, parse_any(&dummy, &kv, &any));
	ck_assert_int_eq(any.size, 3);
	ck_assert_int_eq(any.buf[0], 0x12);
	ck_assert_int_eq(any.buf[1], 0x34);
	ck_assert_int_eq(any.buf[2], 0x56);

	/*
	 * Notice, this is the human-readable value. It later gets DER-encoded,
	 * which might result in some mutations, such as truncated trailing
	 * zeroes on `INTEGER`s:
	 */

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x00000001";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 4);
	ck_assert_int_eq(num.buf[0], 0x00);
	ck_assert_int_eq(num.buf[1], 0x00);
	ck_assert_int_eq(num.buf[2], 0x00);
	ck_assert_int_eq(num.buf[3], 0x01);

	rval = der_encode_to_buffer(&asn_DEF_INTEGER, &num, buf, 64);
	ck_assert_int_eq(3, rval.encoded);
	ck_assert_int_eq(2, buf[0]);
	ck_assert_int_eq(1, buf[1]);
	ck_assert_int_eq(1, buf[2]);

	memset(&any, 0, sizeof(any));
	kv.v.str = "0x00000001";
	ck_assert_pstr_eq(NULL, parse_any(&dummy, &kv, &any));
	ck_assert_int_eq(any.size, 4);
	ck_assert_int_eq(any.buf[0], 0x00);
	ck_assert_int_eq(any.buf[1], 0x00);
	ck_assert_int_eq(any.buf[2], 0x00);
	ck_assert_int_eq(any.buf[3], 0x01);

	rval = der_encode_to_buffer(&asn_DEF_ANY, &any, buf, 64);
	ck_assert_int_eq(4, rval.encoded);
	ck_assert_int_eq(buf[0], 0x00);
	ck_assert_int_eq(buf[1], 0x00);
	ck_assert_int_eq(buf[2], 0x00);
	ck_assert_int_eq(buf[3], 0x01);

	/*
	 * If you want a `BIT STRING` whose bit count is not a multiple of 8,
	 * use hexadecimal or binary format, then a prefix length (which behaves
	 * pretty much like in IP addresses). The following three are
	 * equivalent:
	 */

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0b111110";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 1);
	ck_assert_int_eq(bs.buf[0], 0xF8);
	ck_assert_int_eq(bs.bits_unused, 2);

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0xF8/6";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 1);
	ck_assert_int_eq(bs.buf[0], 0xF8);
	ck_assert_int_eq(bs.bits_unused, 2);

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0b11111/6";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 1);
	ck_assert_int_eq(bs.buf[0], 0xF8);
	ck_assert_int_eq(bs.bits_unused, 2);

	/*
	 * Please note that prefixing swaps the anchoring of the number!
	 * As an `INTEGER`, `0x1234` equals `0x001234`, but `0x1234/24` equals
	 * `0x123400`.
	 */

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x1234";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 2);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x001234";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 3);
	ck_assert_int_eq(num.buf[0], 0x00);
	ck_assert_int_eq(num.buf[1], 0x12);
	ck_assert_int_eq(num.buf[2], 0x34);

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x1234/24";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 3);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);
	ck_assert_int_eq(num.buf[2], 0x00);

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x123400";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 3);
	ck_assert_int_eq(num.buf[0], 0x12);
	ck_assert_int_eq(num.buf[1], 0x34);
	ck_assert_int_eq(num.buf[2], 0x00);

	/*
	 * Prefix lengths give you free padding, I guess. The following two are
	 * equivalent:
	 */

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0x1000000000000000000000000000000000";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 17);
	ck_assert_int_eq(bs.buf[0], 0x10);
	for (i = 1; i < 17; i++)
		ck_assert_int_eq(bs.buf[i], 0);
	ck_assert_int_eq(bs.bits_unused, 0);

	memset(&bs, 0, sizeof(bs));
	kv.v.str = "0x10/136";
	ck_assert_pstr_eq(NULL, parse_bitstr(&dummy, &kv, &bs));
	ck_assert_int_eq(bs.size, 17);
	ck_assert_int_eq(bs.buf[0], 0x10);
	for (i = 1; i < 17; i++)
		ck_assert_int_eq(bs.buf[i], 0);
	ck_assert_int_eq(bs.bits_unused, 0);

	/*
	 * Prefixing is actually also compatible with the other "numeric" data
	 * types, but they actually require the length to be a multiple of 8.
	 * You may abuse this to produce big numbers:
	 */

	memset(&num, 0, sizeof(num));
	kv.v.str = "0x01/1000";
	ck_assert_pstr_eq(NULL, parse_int(&dummy, &kv, &num));
	ck_assert_int_eq(num.size, 125);
	ck_assert_int_eq(num.buf[0], 0x01);
	for (i = 1; i < 125; i++)
		ck_assert_int_eq(num.buf[i], 0);
}
END_TEST

START_TEST(check_parse_oid)
{
	struct kv_value kv;
	OBJECT_IDENTIFIER_t oid;

	kv.type = VALT_STR;

	memset(&oid, 0, sizeof(oid));
	kv.v.str = "1.2.840.113549.1.7.2";
	parse_oid(NULL, &kv, &oid);
	ck_assert_int_eq(oid.size, 9);
	ck_assert_int_eq(oid.buf[0], 0x2A);
	ck_assert_int_eq(oid.buf[1], 0x86);
	ck_assert_int_eq(oid.buf[2], 0x48);
	ck_assert_int_eq(oid.buf[3], 0x86);
	ck_assert_int_eq(oid.buf[4], 0xF7);
	ck_assert_int_eq(oid.buf[5], 0x0D);
	ck_assert_int_eq(oid.buf[6], 0x01);
	ck_assert_int_eq(oid.buf[7], 0x07);
	ck_assert_int_eq(oid.buf[8], 0x02);
}
END_TEST

START_TEST(check_find_last_1_index)
{
	unsigned char bits[16] = { 0 };

	ck_assert_uint_eq(UINT_MAX, find_last_1_index(bits));
	bits[0] = 0x80;
	ck_assert_uint_eq(0, find_last_1_index(bits));
	bits[0] = 0xc0;
	ck_assert_uint_eq(1, find_last_1_index(bits));
	bits[0] = 0xe0;
	ck_assert_uint_eq(2, find_last_1_index(bits));
	bits[0] = 0xe2;
	ck_assert_uint_eq(6, find_last_1_index(bits));
	bits[0] = 0xe3;
	ck_assert_uint_eq(7, find_last_1_index(bits));

	bits[1] = 0x80;
	ck_assert_uint_eq(8, find_last_1_index(bits));
	bits[1] = 0x40;
	ck_assert_uint_eq(9, find_last_1_index(bits));

	bits[2] = 0x80;
	ck_assert_uint_eq(16, find_last_1_index(bits));

	bits[3] = 0xFF;
	ck_assert_uint_eq(31, find_last_1_index(bits));

	bits[15] = 0x80;
	ck_assert_uint_eq(120, find_last_1_index(bits));
	bits[15] = 0xc0;
	ck_assert_uint_eq(121, find_last_1_index(bits));
	bits[15] = 0xfe;
	ck_assert_uint_eq(126, find_last_1_index(bits));
	bits[15] = 0xff;
	ck_assert_uint_eq(127, find_last_1_index(bits));
}
END_TEST

static void
init_kv_set(struct kv_value *input, ...)
{
	char *str;
	struct kv_node *node;
	va_list ap;

	input->type = VALT_SET;
	va_start(ap, input);

	STAILQ_INIT(&input->v.set);
	while ((str = va_arg(ap, char *)) != NULL) {
		node = pzalloc(sizeof(struct kv_node));
		node->value.type = VALT_STR;
		node->value.v.str = pstrdup(str);
		STAILQ_INSERT_TAIL(&input->v.set, node, hook);
	}

	va_end(ap);
}

static void
ck_af(OCTET_STRING_t *family, unsigned int af)
{
	ck_assert_uint_eq(2, family->size);
	ck_assert_uint_eq(0, family->buf[0]);
	ck_assert_uint_eq(af, family->buf[1]);
}

static void
ck_addr(struct ROAIPAddress *addr, size_t size, int bits_unused, ...)
{
	va_list ap;
	size_t i;

	ck_assert_uint_eq(size, addr->address.size);

	va_start(ap, bits_unused);
	for (i = 0; i < size; i++)
		ck_assert_uint_eq(va_arg(ap, int), addr->address.buf[i]);
	va_end(ap);

	ck_assert_int_eq(bits_unused, addr->address.bits_unused);
	ck_assert_ptr_eq(NULL, addr->maxLength);
}

START_TEST(check_parse_ip)
{
	struct kv_value input;
	A_SEQUENCE_OF(struct ROAIPAddressFamily) output;

	init_kv_set(&input, NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
	ck_assert_int_eq(0, output.count);

	/* ========= */

	init_kv_set(&input, "192.0.2.0/24", "2001:db8::/32", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
	ck_assert_int_eq(2, output.count);

	/* IPv4 */
	ck_af(&output.array[0]->addressFamily, 1);
	ck_assert_int_eq(1, output.array[0]->addresses.list.count);
	ck_addr(output.array[0]->addresses.list.array[0], 3, 0, 192, 0, 2);

	/* IPv6 */
	ck_af(&output.array[1]->addressFamily, 2);
	ck_assert_int_eq(1, output.array[1]->addresses.list.count);
	ck_addr(output.array[1]->addresses.list.array[0], 4, 0, 0x20, 0x01, 0x0d, 0xb8);

	/* ========= */

	init_kv_set(&input, "192.0.2.0/24", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
	ck_assert_int_eq(1, output.count);

	ck_af(&output.array[0]->addressFamily, 1);
	ck_assert_int_eq(1, output.array[0]->addresses.list.count);
	ck_addr(output.array[0]->addresses.list.array[0], 3, 0, 192, 0, 2);

	/* ========= */

	init_kv_set(&input, "2001:db8::/32", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
	ck_assert_int_eq(1, output.count);

	ck_af(&output.array[0]->addressFamily, 2);
	ck_assert_int_eq(1, output.array[0]->addresses.list.count);
	ck_addr(output.array[0]->addresses.list.array[0], 4, 0, 0x20, 0x01, 0x0d, 0xb8);

	/* ========= */

	init_kv_set(&input,
	    "192.0.2.0/24", "203.0.113.224/29", "198.51.100.0/130",
	    "2001:db8::/32", "::/0", "2001:db8::ffff/150", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
	ck_assert_int_eq(2, output.count);

	/* IPv4 */
	ck_af(&output.array[0]->addressFamily, 1);
	ck_assert_int_eq(3, output.array[0]->addresses.list.count);
	ck_addr(output.array[0]->addresses.list.array[0], 3, 0,
	    192, 0, 2);
	ck_addr(output.array[0]->addresses.list.array[1], 4, 3,
	    203, 0, 113, 224);
	ck_addr(output.array[0]->addresses.list.array[2], 17, 6,
	    198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	/* IPv6 */
	ck_af(&output.array[1]->addressFamily, 2);
	ck_assert_int_eq(3, output.array[1]->addresses.list.count);
	ck_addr(output.array[1]->addresses.list.array[0], 4, 0,
	    0x20, 0x01, 0x0d, 0xb8);
	ck_addr(output.array[1]->addresses.list.array[1], 0, 0);
	ck_addr(output.array[1]->addresses.list.array[2], 19, 2,
	    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
	    0, 0, 0);

	/* ========= */

	init_kv_set(&input, "192.0.2.0/4", NULL);
	ck_assert_pstr_eq(PREF_TRUNC, parse_ips_roa(NULL, &input, &output));
	init_kv_set(&input, "192.0.2.255/31", NULL);
	ck_assert_pstr_eq(PREF_TRUNC, parse_ips_roa(NULL, &input, &output));
	init_kv_set(&input, "192.0.2.255/32", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));

	init_kv_set(&input, "2001:db8::/2", NULL);
	ck_assert_pstr_eq(PREF_TRUNC, parse_ips_roa(NULL, &input, &output));
	init_kv_set(&input, "2001:db8::ff/127", NULL);
	ck_assert_pstr_eq(PREF_TRUNC, parse_ips_roa(NULL, &input, &output));
	init_kv_set(&input, "2001:db8::ff/128", NULL);
	ck_assert_pstr_eq(NULL, parse_ips_roa(NULL, &input, &output));
}
END_TEST

static Suite *
address_load_suite(void)
{
	Suite *suite;
	TCase *num, *oid, *ip;

	num = tcase_create("Numerics");
	tcase_add_test(num, check_parse_bitstr_hex);
	tcase_add_test(num, check_parse_bitstr_bin);
	tcase_add_test(num, check_parse_int_dec);
	tcase_add_test(num, check_tutorial_examples);

	oid = tcase_create("OID");
	tcase_add_test(oid, check_parse_oid);

	ip = tcase_create("IP");
	tcase_add_test(ip, check_find_last_1_index);
	tcase_add_test(ip, check_parse_ip);

	suite = suite_create("fields");
	suite_add_tcase(suite, num);
	suite_add_tcase(suite, oid);
	suite_add_tcase(suite, ip);
	return suite;
}

int
main(void)
{
	SRunner *runner;
	int tests_failed;

	runner = srunner_create(address_load_suite());
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
