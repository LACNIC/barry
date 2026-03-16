#!/bin/sh

check_output_contains "res-ip" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 0.0.0.0/0 ], [ ::/0 ] ]\"" \
	"auto.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 1.0.0.0/8 ], [ 100::/8 ] ]\"" \
	"overridden-explicit.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/96 ] ]\"" \
	"inherits-explicit.roa,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/96 ] ]\"" \
	"overridden-inherit.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ inherit, inherit ]\"" \
	"inherits-inherit.roa,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ inherit, inherit ]\"" \
	"ta.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 2.0.0.0/8 ], [ 200::/8 ] ]\"" \
	"auto.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 1.3.0.0/16 ], [ 103::/16 ] ]\"" \
	"overridden-explicit.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/96 ] ]\"" \
	"overridden-inherit.mft,obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ inherit, inherit ]\""

check_output_contains "res-as" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x00-0x00FFFFFFFF ]" \
	"auto.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01000000-0x01FFFFFF ]" \
	"overridden-explicit.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01000008-0x01000010 ]" \
	"inherits-explicit.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01000008 ]" \
	"overridden-inherit.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,inherit" \
	"inherits-inherit.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01000000 ]" \
	"ta.mft,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x02000000-0x02FFFFFF ]" \
	"auto.mft,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01030000-0x0103FFFF ]" \
	"overridden-explicit.mft,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x01000008-0x01000010 ]" \
	"overridden-inherit.mft,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,inherit"
