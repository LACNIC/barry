#!/bin/sh

check_output_contains "name-inheritance" -Fx \
	"ta.red.blue.crl,type,File Type,crl" \
	"ta.red.blue.mft,type,File Type,mft" \
	"ta.red.blue.cer,rpp.uri,C String,rsync://localhost:8873/rpki/ta.red.blue" \
	"A.yellow.crl,type,File Type,crl" \
	"A.yellow.mft,type,File Type,mft" \
	"A.yellow.cer,rpp.uri,C String,rsync://localhost:8873/rpki/A.yellow" \
	"BBBB.orange.crl,type,File Type,crl" \
	"BBBB.green.mft,type,File Type,mft" \
	"B.purple.cer,rpp.uri,C String,rsync://localhost:8873/rpki/B.purple"
