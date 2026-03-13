#!/bin/sh

check_output_contains "tutorial-res-override" -Fx \
	"TA.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 0.0.0.0/0 ], [ ::/0 ] ]\"" \
	"CA1.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 1.0.0.0/8 ], [ 100::/8 ] ]\"" \
	"CA2.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),[ [ 6.6.6.0/24 ] ]" \
	"CA3.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),[ [ 6.6.6.0/24 ] ]" \
	"CA4.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),[ [ 6.6.6.0/24 ] ]"

check_output_contains "tutorial-res-ee" -Fx \
	"a.roa,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 1.0.0.0/8 ], [ 100::/8 ] ]\"" \
	"a.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x00 ]" \
	"a.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ inherit, inherit ]\"" \
	"a.mft,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,inherit" \
	"4-only.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),[ inherit ]" \
	"6-only.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),[ inherit ]"
