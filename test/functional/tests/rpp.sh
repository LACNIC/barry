#!/bin/sh

check_output_contains "rpp" -Fx \
	"ta.cer,uri,C String,https://abc" \
	"ta.cer,path,C String,custom/rpp-test/ta" \
	"ta.cer,rpp.uri,C String,rsync://caRepo/rpp-ta" \
	"ta.cer,rpp.path,C String,custom/rpp-test/rpp-ta" \
	"ta.cer,rpp.notification,C String,https://rpkiNotif" \
	"A.cer,uri,C String,rsync://caRepo/rpp-ta/A.cer" \
	"A.cer,path,C String,custom/rpp-test/rpp-ta/A.cer" \
	"A.cer,rpp.uri,C String,rsync://localhost:8873/rpki/A" \
	"A.cer,rpp.path,C String,A" \
	"A.cer,rpp.notification,C String,https://rpkiNotif" \
	"B.crl,uri,C String,rsync://caRepo/rpp-ta/B.crl" \
	"B.crl,path,C String,custom/rpp-test/rpp-ta/B.crl" \
	"C.mft,uri,C String,rsync://caRepo/rpp-ta/C.mft" \
	"C.mft,path,C String,custom/rpp-test/rpp-ta/C.mft" \
	"D.roa,uri,C String,rsync://caRepo/rpp-ta/D.roa" \
	"D.roa,path,C String,custom/rpp-test/rpp-ta/D.roa"
