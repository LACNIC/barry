#!/bin/sh

check_output_contains "obj0" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"

check_output_contains "obj1" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"

check_output_contains "obj2" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"
