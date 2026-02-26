#!/bin/sh

check_output_contains "tutorial-oid" -Fx \
	"roa1.roa,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)"
