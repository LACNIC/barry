#!/bin/sh

check_output_contains "root-only" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/ta.mft" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8443/rrdp/notification.xml"

check_output_contains "sia1" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8443/rrdp/notification.xml" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft"

check_output_contains "sia2" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.2.3.4" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,1.2.4.6" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,OCTET STRING," \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://aaaaaa" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://bbbbbb" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.2.840.113549.1.1.11 (sha256WithRSAEncryption)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,2.16.840.1.101.3.4.2.1 (sha256)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,"

check_output_contains "sia3" -Fx \
	"A.cer,obj.tbsCertificate.extensions,Extensions,\"[ aia, sia ]\"" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8443/rrdp/notification.xml" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"[ aia, sia ]\"" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft" \
	"C.crl,obj.tbsCertList.crlExtensions,Extensions,\"[ aia, sia ]\"" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.1 (Authority Information Access)" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.critical,BOOLEAN,false" \
	"C.crl,obj.tbsCertList.crlExtensions.sia.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.11 (Subject Information Access)" \
	"C.crl,obj.tbsCertList.crlExtensions.sia.critical,BOOLEAN,false"

check_output_contains "sia4" -Fx \
	"A.cer,obj.tbsCertificate.extensions,Extensions,\"[ aia1, sia1, sia2, aia2 ]\"" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessLocation.value,IA5String," \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.value,IA5String," \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.value,OCTET STRING," \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.value,IA5String,type defaults to uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessLocation.type,GeneralName type,rfc822Name" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"[ sia1, sia2, aia ]\"" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.value,IA5String,IA5String" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions,Extensions,\"[ sia1, sia2, aia ]\"" \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.0.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.sia1.extnValue.1.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.sia2.extnValue.1.accessLocation.value,IA5String,striiiiiiing" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,1.4.8.16"
