#!/bin/sh

# If $1 exists, only tests involving a matching RD will be run.
ACCEPT_RD="$1"

# We normally want to test the latest patch; compile that.
cd ../..
make > /dev/null
cd "test/functional"

# Prepare test sandbox
mkdir -p "sandbox/keys"
mkdir -p "sandbox/output"
mkdir -p "sandbox/rrdp"
mkdir -p "sandbox/rsync"
mkdir -p "sandbox/tal"

if [ -z "$(ls -A sandbox/keys)" ]; then    # "If sandbox/keys is empty"
	for i in $(seq 0 20); do
		echo "Creating sandbox/keys/$i.pem"
		openssl genrsa -out "sandbox/keys/$i.pem" 2048
	done
fi

rm -rf sandbox/output/*
rm -rf sandbox/rrdp/*
rm -rf sandbox/rsync/*
rm -rf sandbox/tal/*

# Prepare common barry arguments, needed by all tests
BARRY="../../src/barry"
RSYNC_PATH="--rsync-path sandbox/rsync"
RRDP_PATH="--rrdp-path sandbox/rrdp"
KEYS="--keys sandbox/keys"
PRINTS="-vvp csv"
TIMES="--now 2025-01-01T00:00:00Z --later 2026-01-01T00:00:00Z"
BASIC_ARGS="$RSYNC_PATH $RRDP_PATH $KEYS $PRINTS $TIMES"

# Cache default outputs.
# (Several tests want to compare their outputs to these.)
DEFAULT_OUTPUT_FILE="sandbox/output/root-only.log"
$BARRY $BASIC_ARGS						\
	--tal-path "sandbox/tal/root-only.tal"			\
	"rd/root-only.rd"					\
	> "$DEFAULT_OUTPUT_FILE" 2>&1

check_output_contains() {
	# $1: Test RD filename, without extension
	TEST_RD="$1"
	# $2: Arguments to grep
	GREP_ARGS="$2"
	# $3-$n: Regular expression that describes the line that should be
	# present in the test output

	if [ ! -z "$ACCEPT_RD" -a "$TEST_RD" != "$ACCEPT_RD" ]; then
		return
	fi

	OUTPUT_FILE="sandbox/output/$TEST_RD.log"
	if [ ! -f "$OUTPUT_FILE" ]; then
		$BARRY $BASIC_ARGS				\
			--tal-path "sandbox/tal/$TEST_RD.tal"	\
			"rd/$TEST_RD.rd"			\
			> "$OUTPUT_FILE" 2>&1
		RETVAL="$?"
		if [ "$RETVAL" -eq 0 ]; then
			SUCCESSES=$((SUCCESSES+1))
		else
			echo "ERR: Barry returned nonzero in test '$TEST_RD': $RETVAL"
			echo "     (See $OUTPUT_FILE)"
			FAILS=$((FAILS+1))
			return
		fi
	fi

	shift
	shift
	while test $# -gt 0; do
		grep $GREP_ARGS "$1" "$OUTPUT_FILE" > /dev/null
		if [ $? -eq 0 ]; then
			SUCCESSES=$((SUCCESSES+1))
		else
			echo "ERR: Test '$TEST_RD' did not output '$1'"
			echo "     (See $OUTPUT_FILE)"
			FAILS=$((FAILS+1))
		fi

		shift
	done
}

check_tutorial_delta() {
	if [ ! -z "$ACCEPT_RD" -a "delta" != "$ACCEPT_RD" ]; then
		return
	fi

	$BARRY $KEYS $PRINTS $TIMES \
		--tal-path "sandbox/tal/delta.old.tal" \
		--rsync-path sandbox/rsync/old/ \
		--rrdp-path sandbox/rrdp/old/ \
		rd/tutorial-delta-old.rd \
		> /dev/null 2> /dev/null
	$BARRY $KEYS $PRINTS $TIMES \
		--tal-path "sandbox/tal/delta.new.tal" \
		--rsync-path sandbox/rsync/new/ \
		--rrdp-path sandbox/rrdp/new/ \
		rd/tutorial-delta-new.rd \
		> /dev/null 2> /dev/null
	mkdir -p sandbox/rrdp/fusion/
	${BARRY}-delta -v \
		--old.notification    sandbox/rrdp/old/notif.xml \
		--old.snapshot        sandbox/rrdp/old/snapshot.xml \
		--new.notification    sandbox/rrdp/new/notif.xml \
		--new.snapshot        sandbox/rrdp/new/snapshot.xml \
		--output.notification sandbox/rrdp/fusion/notif.xml \
		--output.delta.path   sandbox/rrdp/fusion/delta.xml \
		--output.delta.uri    https://your-server.net/rrdp/v2/delta.xml \
		> "sandbox/output/delta.log" 2>&1
	check_output_contains "delta" -F \
		"rsync://localhost:8873/rpki/ca1/roa1B.roa disappeared; adding withdraw" \
		"rsync://localhost:8873/rpki/ca1/ca1.mft has a different hash; adding publish" \
		"rsync://localhost:8873/rpki/ca1/roa1C.roa spawned; adding publish"
}

SUCCESSES=0
FAILS=0

HEXNUM="0x[0-9A-F][0-9A-F]*"

check_output_contains "tutorial-num" -Fx \
	"1.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"2.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"3.cer,obj.tbsCertificate.version,INTEGER,0x1234" \
	"1.cer,obj.tbsCertificate.extensions.bc.critical,BOOLEAN,true" \
	"ta.mft,obj.content.signerInfos.0.signature,OCTET STRING,0x1234" \
	"1.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1234" \
	"1.cer,obj.tbsCertificate.signature.parameters,ANY,0x1234" \
	"2.cer,obj.tbsCertificate.signature.parameters,ANY,0x123456" \
	"3.cer,obj.tbsCertificate.signature.parameters,ANY,0x123456" \
	"4.cer,obj.tbsCertificate.signature.parameters,ANY,0x00A100A200A300A400A500A600A700A880B180B280B380B480B580B680B780B8A0C1A0C2A0C3A0C4A0C500C6A0C7A0C8F0D1F0D2F0D3F0D4F0D5F0D6F0D7F0" \
	"4.cer,obj.tbsCertificate.version,INTEGER,0x00000001" \
	"5.cer,obj.tbsCertificate.signature.parameters,ANY,0x00000001" \
	"2.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"3.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"4.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"5.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"6.cer,obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"5.cer,obj.tbsCertificate.version,INTEGER,0x0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

check_output_contains "tutorial-bool" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ta.cer,obj.tbsCertificate.extensions.asn.critical,BOOLEAN,true" \
	"ta.cer,obj.tbsCertificate.extensions.ski.critical,BOOLEAN,false"

check_output_contains "tutorial-oid" -Fx \
	"roa1.roa,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)"

check_output_contains "tutorial-date" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,2025-07-15T19:39:38Z"

check_output_contains "tutorial-name" -Fx \
	"ta.cer,obj.tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ta.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,ta.cer" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,aaa" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.1.type,OBJECT IDENTIFIER,2.5.4.5 (serialNumber)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.1.value,PrintableString in ANY,bbb" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.0.type,OBJECT IDENTIFIER,2.5.4.4 (surname)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.0.value,PrintableString in ANY,ccc" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.1.type,OBJECT IDENTIFIER,2.5.4.42 (givenName)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.1.value,PrintableString in ANY,ddd" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.2.type,OBJECT IDENTIFIER,2.5.4.43 (initials)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.2.value,PrintableString in ANY,eee"

check_output_contains "tutorial-ext" -Fx \
	"ta.cer,obj.tbsCertificate.extensions,Extensions,\"{ bc=bc, ski=ski, ku=ku, sia=sia, cp=cp, ip=ip, asn=asn }\"" \
	"ca1.cer,obj.tbsCertificate.extensions,Extensions,\"{ bc=bc, ski=ski, aki=aki, ku=ku, crldp=crldp, aia=aia, sia=sia, cp=cp, ip=ip, asn=asn }\"" \
	"roa1.roa,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"{ ski=ski, aki=aki, ku=ku, crldp=crldp, aia=aia, sia=sia, cp=cp, ip=ip, asn=asn }\"" \
	"ta.crl,obj.tbsCertList.crlExtensions,Extensions,\"{ aki=aki, crln=crln }\"" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.28 (sbgp-ipAddrBlockv2)" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ca1.cer,obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"[ [ 192.0.2.0/24 ], [ 2001:db8::/96 ] ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions.asn.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.29 (sbgp-autonomousSysNumv2)" \
	"ca1.cer,obj.tbsCertificate.extensions.asn.critical,BOOLEAN,true" \
	"ca1.cer,obj.tbsCertificate.extensions.asn.extnValue.asnum,AS Resources,\"[ 0x1234, 0x5678 ]\"" \
	"ca1.cer,obj.tbsCertificate.extensions.asn.extnValue.rdi,AS Resources,\"[ 0x9ABC, 0xDEF0 ]\"" \
	"ca2.cer,obj.tbsCertificate.extensions,Extensions,\"{ ip=ip, asn=asn }\"" \
	"ca2.cer,obj.tbsCertificate.extensions.ip.extnID,OBJECT IDENTIFIER,1.2.3.4.5" \
	"ca3.cer,obj.tbsCertificate.extensions,Extensions,\"{ red=ip, blue=asn, yellow=ip, purple=bc, orange=ip, green=asn }\"" \
	"ca3.cer,obj.tbsCertificate.extensions.orange.extnID,OBJECT IDENTIFIER,1.2.3.4.5"

check_output_contains "tutorial-ip" -Fx \
	"roa1.roa,obj.content.encapContentInfo.eContent.ipAddrBlocks,IP Resources (ROA),\"[ [ 192.0.2.0/24, 203.0.113.0/32 ], [ 2001:db8::/40-48 ] ]\""

check_output_contains "tutorial-rrdp1" -Fx \
	"ta.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"A.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"B.cer,rpp.notification,C String,https://tomato/rrdp/notification.xml" \
	"B2.cer,rpp.notification,C String,https://lettuce/rrdp/notification.xml" \
	"https://potato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ A.cer, A1.roa, A2.roa, A.mft, A.crl, B.cer, ta.mft, ta.crl ]\"" \
	"https://tomato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B1.roa, B2.cer, B.mft, B.crl ]\"" \
	"https://lettuce/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B2a.roa, B2.mft, B2.crl ]\""
check_output_contains "tutorial-rrdp2" -Fx \
	"ta.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"A.cer,rpp.notification,C String,https://potato/rrdp/notification.xml" \
	"B.cer,rpp.notification,C String,https://tomato/rrdp/notification.xml" \
	"B2.cer,rpp.notification,C String,https://lettuce/rrdp/notification.xml" \
	"https://potato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ A.cer, A1.roa, A2.roa, A.mft, A.crl, B.cer, ta.mft, ta.crl ]\"" \
	"https://tomato/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ ta.cer, A1.roa, A1.roa, B2a.roa ]\"" \
	"https://lettuce/rrdp/notification.xml,snapshot.files,Snapshot Files,\"[ B2a.roa, B2.mft, B2.crl ]\""

check_tutorial_delta

check_output_contains "root-only-signature" -Fx "ta.cer,obj.signature,BIT STRING,0x010203"
check_output_contains "root-only" -x "ta\\.cer,obj\\.signature,BIT STRING,$HEXNUM"
check_output_contains "root-only-signature-crl" -Fx "0.crl,obj.signature,BIT STRING,0x010203"
check_output_contains "root-only" -x "ta\\.crl,obj\\.signature,BIT STRING,$HEXNUM"

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

check_output_contains "type" -Fx \
	"ta.cer,type,File Type,cer" \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x02" \
	"roa.roa,type,File Type,cer" \
	"roa.roa,obj.tbsCertificate.version,INTEGER,0x02" \
	"certificate.cer,type,File Type,roa" \
	"certificate.cer,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.24 (id-ct-routeOriginAuthz)" \
	"crl.crl,type,File Type,mft" \
	"crl.crl,obj.content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)" \
	"manifest.mft,type,File Type,crl" \
	"manifest.mft,obj.tbsCertList.version,INTEGER,0x01"

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

check_output_contains "tutorial-filelist-default" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "tutorial-filelist-default-explicit" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "tutorial-filelist-crl-omitted" -x \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=$HEXNUM, B\\.cer=$HEXNUM, ta\\.crl=$HEXNUM }\""
check_output_contains "tutorial-filelist-overrides-isolated" -x \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=0x010203, potatoes=0 }\""
check_output_contains "tutorial-filelist-overrides-full" -x \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=0x010203, nonexistent\\.cer=0x040506, mft\\.mft=0x112233, foobar=0x55555555555555 }\""

check_output_contains "eContent" -Fx \
	"0.mft,obj.content.encapContentInfo.eContent,ANY,0xAABBCC"

check_output_contains "obj0" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"
check_output_contains "obj1" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"
check_output_contains "obj2" -Fx \
	"ta.cer,obj.tbsCertificate.version,INTEGER,0x04" \
	"ta.cer,obj.tbsCertificate.serialNumber,INTEGER,0x05" \
	"ta.cer,obj.tbsCertificate.signature.algorithm,OBJECT IDENTIFIER,1.2.3.4" \
	"ta.cer,obj.tbsCertificate.signature.parameters,ANY,0x0607"

check_output_contains "notification-1" -Fx \
	"https://localhost:8080/rpki/notification-1.xml,path,C String,notification-1.xml" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.uri,C String,https://localhost:8080/rpki/notification-1.xml.snapshot" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.path,C String,notification-1.xml.snapshot" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.files,Snapshot Files,\"[ ta.mft, ta.crl ]\""
check_output_contains "notification-2" -Fx \
	"https://localhost:8080/rpki/notification-2.xml,path,C String,notification-2.xml" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.uri,C String,https://localhost:8080/rpki/notification-2.xml.snapshot" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.path,C String,notification-2.xml.snapshot" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.files,Snapshot Files,\"[ A.cer, A.roa, A.mft, A.crl, B.cer, B.mft, B.crl, ta.mft, ta.crl ]\""

check_output_contains "root-only" -Fx \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/ta.mft" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"ta.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8080/rpki/notification.xml"
check_output_contains "gname" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,rfc822Name" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,yeah sure" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,OCTET STRING,0x010203" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,registeredID" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"B.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String," \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"C.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,separate"

check_output_contains "sia1" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8080/rpki/notification.xml" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft"

check_output_contains "sia2" -Fx \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.2.3.4" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,1.2.4.6" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,OCTET STRING," \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://aaaaaa" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://bbbbbb" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.2.840.113549.1.1.11 (sha256WithRSAEncryption)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,2.16.840.1.101.3.4.2.1 (sha256)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,"

check_output_contains "sia3" -Fx \
	"A.cer,obj.tbsCertificate.extensions,Extensions,\"{ aia=aia, sia=sia }\"" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia.extnValue.2.accessLocation.value,IA5String,https://localhost:8080/rpki/notification.xml" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"{ aia=aia, sia=sia }\"" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft" \
	"C.crl,obj.tbsCertList.crlExtensions,Extensions,\"{ aia=aia, sia=sia }\"" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.1 (Authority Information Access)" \
	"C.crl,obj.tbsCertList.crlExtensions.aia.critical,BOOLEAN,false" \
	"C.crl,obj.tbsCertList.crlExtensions.sia.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.11 (Subject Information Access)" \
	"C.crl,obj.tbsCertList.crlExtensions.sia.critical,BOOLEAN,false"

check_output_contains "sia4" -Fx \
	"A.cer,obj.tbsCertificate.extensions,Extensions,\"{ aia1=aia, sia1=sia, sia2=sia, aia2=aia }\"" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia1.extnValue.1.accessLocation.value,IA5String," \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.10 (RPKI Manifest)" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/A/A.mft" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.value,IA5String," \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.type,GeneralName type,iPAddress" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.value,OCTET STRING," \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.value,IA5String,type defaults to uniformResourceIdentifier" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessLocation.type,GeneralName type,rfc822Name" \
	"A.cer,obj.tbsCertificate.extensions.aia2.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions,Extensions,\"{ sia1=sia, sia2=sia, aia=aia }\"" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue.1.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta/B.mft" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.type,GeneralName type,dNSName" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.0.accessLocation.value,IA5String," \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue.1.accessLocation.value,IA5String,IA5String" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.2 (CA Issuers)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0.accessLocation.value,IA5String,rsync://localhost:8873/rpki/ta.cer" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.13 (RPKI Notify)" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"B.mft,obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.1.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions,Extensions,\"{ 1=sia, 2=sia, 3=aia }\"" \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.0.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.0.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.1.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.11 (Signed Object)" \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.1.extnValue.1.accessLocation.value,IA5String," \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.0.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.1.accessMethod,OBJECT IDENTIFIER,<absent>" \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.1.accessLocation.type,GeneralName type,uniformResourceIdentifier" \
	"C.crl,obj.tbsCertList.crlExtensions.2.extnValue.1.accessLocation.value,IA5String,striiiiiiing" \
	"C.crl,obj.tbsCertList.crlExtensions.3.extnValue.0.accessMethod,OBJECT IDENTIFIER,1.3.6.1.5.5.7.48.5 (CA Repository)" \
	"C.crl,obj.tbsCertList.crlExtensions.3.extnValue.0.accessLocation.type,GeneralName type,registeredID" \
	"C.crl,obj.tbsCertList.crlExtensions.3.extnValue.0.accessLocation.value,OBJECT IDENTIFIER,1.4.8.16"

echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
