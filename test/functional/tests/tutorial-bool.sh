#!/bin/sh

check_output_contains "tutorial-bool" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ta.cer,obj.tbsCertificate.extensions.as.critical,BOOLEAN,true" \
	"ta.cer,obj.tbsCertificate.extensions.ski.critical,BOOLEAN,false"
