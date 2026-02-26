#!/bin/sh

check_output_contains "alt-eContent" -Fx \
	"raw.mft,obj.content.encapContentInfo.eContent,OCTET STRING,0x010203" \
	"encoded.mft,obj.content.encapContentInfo.eContent.manifestNumber,INTEGER,0x05" \
	"raw.roa,obj.content.encapContentInfo.eContent,OCTET STRING,0x020304" \
	"encoded.roa,obj.content.encapContentInfo.eContent.asId,INTEGER,0xAABBCC" \
	"raw.asa,obj.content.encapContentInfo.eContent,OCTET STRING,0x050607" \
	"encoded.asa,obj.content.encapContentInfo.eContent.version,INTEGER,0x04" \
	"encoded.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x0200" \
	"encoded.asa,obj.content.encapContentInfo.eContent.providers,ASPA Providers,\"[ 0x0100, 0x0300, 0x0400, 0x0555 ]\""
