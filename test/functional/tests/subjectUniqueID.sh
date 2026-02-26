#!/bin/sh

check_output_contains "subjectUniqueID" -Fx \
	"empty.cer,obj.tbsCertificate.subjectUniqueID,BIT STRING," \
	"populated.cer,obj.tbsCertificate.subjectUniqueID,BIT STRING,0x332211"
