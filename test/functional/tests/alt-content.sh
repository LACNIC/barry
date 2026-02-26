#!/bin/sh

check_output_contains "alt-content" -Fx \
	"raw.mft,obj.content,ANY,0x010203" \
	"encoded.mft,obj.content.version,INTEGER,0x05" \
	"raw.roa,obj.content,ANY,0x020304" \
	"encoded.roa,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"raw.asa,obj.content,ANY,0x050607" \
	"encoded.asa,obj.content.encapContentInfo.eContent.customerASID,INTEGER,0x0100"
