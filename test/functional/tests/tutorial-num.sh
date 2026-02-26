#!/bin/sh

check_output_contains "tutorial-num" -Fx \
	"1.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"2.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"3.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"1.cer,obj.tbsCertificate.extensions.bc.critical,BOOLEAN,true" \
	"ta.mft,obj.content.signerInfos.0.signature,OCTET STRING,0x1234" \
	"1.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1234" \
	"1.cer,obj.tbsCertificate.signature.parameters,ANY,0x1234" \
	"2.cer,obj.tbsCertificate.signature.parameters,ANY,0x123456" \
	"3.cer,obj.tbsCertificate.signature.parameters,ANY,0x123456" \
	"4.cer,obj.tbsCertificate.signature.parameters,ANY,0x00A100A200A300A400A500A600A700A880B180B280B380B480B580B680B780B8A0C1A0C2A0C3A0C4A0C500C6A0C7A0C8F0D1F0D2F0D3F0D4F0D5F0D6F0D7F0" \
	"4.cer,obj.tbsCertificate.version,INTEGER,0x00000001" \
	"5.cer,obj.tbsCertificate.signature.parameters,ANY,0x00000001" \
	"2.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"3.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"4.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"5.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"6.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"5.cer,obj.tbsCertificate.version,INTEGER,0x0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
