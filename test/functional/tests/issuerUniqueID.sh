#!/bin/sh

check_output_contains "issuerUniqueID" -Fx \
	"empty.cer,obj.tbsCertificate.issuerUniqueID,BIT STRING," \
	"populated.cer,obj.tbsCertificate.issuerUniqueID,BIT STRING,0x112233"
