#!/bin/sh

check_output_contains "type" -Fx \
	"ta.cer,type,File Type,cer" \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x02" \
	"roa.roa,type,File Type,cer" \
	"roa.roa,obj.tbsCertificate.version,INTEGER,0x02" \
	"certificate.cer,type,File Type,roa" \
	"certificate.cer,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.24 (id-ct-routeOriginAuthz)" \
	"crl.crl,type,File Type,mft" \
	"crl.crl,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)" \
	"manifest.mft,type,File Type,crl" \
	"manifest.mft,obj.tbsCertList.version,INTEGER,0x01"
