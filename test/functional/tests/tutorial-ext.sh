#!/bin/sh

check_output_contains "tutorial-ext" -Fx \
	"ta.cer,obj.tbsCertificate.extensions,Extensions,\"[ bc, ski, ku, sia, cp, ip, as ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions,Extensions,\"[ bc, ski, aki, ku, cdp, aia, sia, cp, ip, as ]\"" \
	"roa1.roa,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"[ ski, aki, ku, cdp, aia, sia, cp, ip ]\"" \
	"ta.crl,obj.tbsCertList.crlExtensions,Extensions,\"[ aki, cn ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.28 (sbgp-ipAddrBlockv2)" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/96 ] ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions.as.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.29 (sbgp-autonomousSysNumv2)" \
	"ca1.cer,obj.tbsCertificate.extensions.as.critical,BOOLEAN,true" \
	"ca1.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,\"[ 0x1234, 0x5678 ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions.as.extnValue.rdi,AS Resources,\"[ 0x9ABC, 0xDEF0 ]\"" \
	"ca2.cer,obj.tbsCertificate.extensions,Extensions,\"[ ip, as ]\"" \
	"ca2.cer,obj.tbsCertificate.extensions.ip.extnID,OBJECT IDENTIFIER,1.2.3.4.5" \
	"ca3.cer,obj.tbsCertificate.extensions,Extensions,\"[ ip1, as1, ip2, bc, ip3, as2 ]\"" \
	"ca3.cer,obj.tbsCertificate.extensions.ip3.extnID,OBJECT IDENTIFIER,1.2.3.4.5"
