ta.cer
	1.cer
	2.cer
	3.cer
	4.cer
	5.cer
	6.cer
	ta.mft

# INTEGER

[1.cer]
tbsCertificate.version = 4660
[2.cer]
tbsCertificate.version = 0x1234
[3.cer]
tbsCertificate.version = 0b0001001000110100

# BOOLEAN

[1.cer]
tbsCertificate.extensions.bc.critical = 9999

# OCTET STRING

[ta.mft]
content.signerInfos.0.signature = 4660

# BIT STRING

[1.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1234

# ANY

[1.cer]
tbsCertificate.signature.parameters = 0b0001001000110100

# "Arrays"

[2.cer]
tbsCertificate.signature.parameters = 0x123456
[3.cer]
tbsCertificate.signature.parameters = "0b_0001:0010_0011,0100 0101 0110"
[4.cer]
tbsCertificate.signature.parameters = "0x
	00a1 00a2 00a3 00a4 00a5 00a6 00a7 00a8
	80b1 80b2 80b3 80b4 80b5 80b6 80b7 80b8
	A0c1 A0c2 A0c3 A0c4 A0c5 00c6 A0c7 A0c8
	F0d1 F0d2 F0d3 F0d4 F0d5 F0d6 F0d7 F0
"

# DER-encoding

[4.cer]
tbsCertificate.version = 0x00000001
[5.cer]
tbsCertificate.signature.parameters = 0x00000001

# Prefix lengths

[2.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b:11:11:10
[3.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0xF8/6
[4.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b11111/6

# Padding

[5.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1000000000000000000000000000000000
[6.cer]
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x10/136
[5.cer]
tbsCertificate.version = 0x01/1000
