#!/bin/sh

FILELIST="obj\\.content\\.encapContentInfo\\.eContent\\.fileList"

check_output_contains "root-only" -x \
	"ta\\.mft,$FILELIST,File List,{ ta\\.crl=$HEXNUM }" \
	"ta\\.mft,$FILELIST\\.0\\.file,IA5String,ta\\.crl" \
	"ta\\.mft,$FILELIST\\.0\\.hash,BIT STRING,$HEXNUM"
check_output_contains "filelist-str" -x \
	"0\\.mft,$FILELIST,File List,\"{ =0, =0, =0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-str-extra" -x \
	"0\\.mft,$FILELIST,File List,\"{ =0, fake=0, =0x0102 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,fake" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x0102"
check_output_contains "filelist-set" -x \
	"0\\.mft,$FILELIST,File List,\"{ no1=0, 0\\.crl=$HEXNUM, no2=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,no2" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-set-extra" -x \
	"0\\.mft,$FILELIST,File List,\"{ no1=0x0304, 0\\.crl=$HEXNUM, yes=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x0304" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,yes" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-map" -x \
	"0\\.mft,$FILELIST,File List,\"{ a=0x01, b=0x02, c=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0x02" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,c" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x03"
check_output_contains "filelist-map-extra" -x \
	"0\\.mft,$FILELIST,File List,\"{ a=0x01, b=0x10, ddd=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0x10" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,ddd" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x03"
