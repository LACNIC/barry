ta.cer
	1.cer
	2.cer
	3.cer
	4.cer
	5.cer
	6.cer
	ta.mft

# INTEGER

[node: 1.cer]
obj.tbsCertificate.version = 4660
[node: 2.cer]
obj.tbsCertificate.version = 0x1234
[node: 3.cer]
obj.tbsCertificate.version = 0b0001001000110100

# BOOLEAN

[node: 1.cer]
obj.tbsCertificate.extensions.bc.critical = 9999

# OCTET STRING

[node: ta.mft]
obj.content.signerInfos.0.signature = 4660

# BIT STRING

[node: 1.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1234

# ANY

[node: 1.cer]
obj.tbsCertificate.signature.parameters = 0b0001001000110100

# "Arrays"

[node: 2.cer]
obj.tbsCertificate.signature.parameters = 0x123456
[node: 3.cer]
obj.tbsCertificate.signature.parameters = "0b_0001:0010_0011,0100 0101 0110"
[node: 4.cer]
obj.tbsCertificate.signature.parameters = "0x
	00a1 00a2 00a3 00a4 00a5 00a6 00a7 00a8
	80b1 80b2 80b3 80b4 80b5 80b6 80b7 80b8
	A0c1 A0c2 A0c3 A0c4 A0c5 00c6 A0c7 A0c8
	F0d1 F0d2 F0d3 F0d4 F0d5 F0d6 F0d7 F0
"

# DER-encoding

[node: 4.cer]
obj.tbsCertificate.version = 0x00000001
[node: 5.cer]
obj.tbsCertificate.signature.parameters = 0x00000001

# Prefix lengths

[node: 2.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b:11:11:10
[node: 3.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0xF8/6
[node: 4.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b11111/6

# Padding

[node: 5.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1000000000000000000000000000000000
[node: 6.cer]
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x10/136
[node: 5.cer]
obj.tbsCertificate.version = 0x01/1000
