#!/bin/sh

check_output_contains "aspa-min" -Fx \
	"aspa.asa,obj.content.encapContentInfo.eContent.version,INTEGER,0x01" \
	"aspa.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x01000000" \
	"aspa.asa,obj.content.encapContentInfo.eContent.providers,ASPA Providers,[ 0 ]"

check_output_contains "aspa-max" -Fx \
	"aspa.asa,obj.content.encapContentInfo.eContent.version,INTEGER,0x04" \
	"aspa.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x0200" \
	"aspa.asa,obj.content.encapContentInfo.eContent.providers,ASPA Providers,\"[ 0x0100, 0x0300, 0x0400, 0x0555 ]\""
