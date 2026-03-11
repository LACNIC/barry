#!/bin/sh

check_output_contains "as-single" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,\"[ 0x10, 0x20, 0x30 ]\"" \
	"ta.cer,obj.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"ca.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,\"[ 0x10, 0x20 ]\"" \
	"ca.cer,obj.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"aspa.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x20 ]" \
	"aspa.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"aspa.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x20" \
	"aspa.asa,obj.content.encapContentInfo.eContent.providers,ASPA Providers,[ 0x0100 ]"

check_output_contains "as-range" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,\"[ 0x10-0x20, 0x30-0x40, 0x1000-0x1234 ]\"" \
	"ta.cer,obj.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"ca.cer,obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x02-0x08 ]" \
	"ca.cer,obj.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"aspa.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources,[ 0x04-0x06 ]" \
	"aspa.asa,obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.rdi,AS Resources," \
	"aspa.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x05" \
	"aspa.asa,obj.content.encapContentInfo.eContent.providers,ASPA Providers,[ 0x0100 ]"
