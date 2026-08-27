#!/bin/sh

check_output_contains "eku-default" -Fx \
	"ta.cer,obj.tbsCertificate.extensions,Extensions,[ eku ]" \
	"ta.cer,obj.tbsCertificate.extensions.eku.extnID,OBJECT IDENTIFIER,2.5.29.37 (X509v3 Extended Key Usage)" \
	"ta.cer,obj.tbsCertificate.extensions.eku.critical,BOOLEAN,false" \
	"ta.cer,obj.tbsCertificate.extensions.eku.extnValue,Extended Key Usage,[ ]"

check_output_contains "eku-normal" -Fx \
	"ta.cer,obj.tbsCertificate.extensions,Extensions,\"[ bc, eku ]\"" \
	"ta.cer,obj.tbsCertificate.extensions.eku.extnID,OBJECT IDENTIFIER,2.5.29.37 (X509v3 Extended Key Usage)" \
	"ta.cer,obj.tbsCertificate.extensions.eku.critical,BOOLEAN,false" \
	"ta.cer,obj.tbsCertificate.extensions.eku.extnValue,Extended Key Usage,\"[ 2.5.29.37 (X509v3 Extended Key Usage), 1.2.840.113549.1.1.11 (sha256WithRSAEncryption), 2.5.4.3 (commonName) ]\""
