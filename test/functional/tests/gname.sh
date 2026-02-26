#!/bin/sh

check_output_contains "gname" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,rfc822Name" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,yeah sure" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,OCTET STRING,0x010203" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,registeredID" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String," \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,separate"
