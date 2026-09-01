#!/bin/sh

check_output_contains "gnames" -Fx \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.0.type,GeneralName type,rfc822Name" \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.0.value,IA5String,achoo" \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.1.type,GeneralName type,iPAddress" \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.1.value,OCTET STRING,0x01020304" \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.2.type,GeneralName type,registeredID" \
	"ca.cer,obj.tbsCertificate.extensions.aki.extnValue.authorityCertIssuer.2.value,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)"
