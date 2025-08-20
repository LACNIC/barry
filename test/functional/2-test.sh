#!/bin/sh

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
	# $2-$n: Regular expression that describes the line that should be
	# present in the test output

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
		fi
	fi

	shift
	while test $# -gt 0; do
		grep -x "$1" "$OUTPUT_FILE" > /dev/null
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

SUCCESSES=0
FAILS=0

HEXNUM="0x[0-9A-F][0-9A-F]*"

check_output_contains "tutorial-num" \
	"1.cer,tbsCertificate.version,INTEGER,0x1234" \
	"2.cer,tbsCertificate.version,INTEGER,0x1234" \
	"3.cer,tbsCertificate.version,INTEGER,0x1234" \
	"1.cer,tbsCertificate.extensions.bc.critical,BOOLEAN,true" \
	"ta.mft,content.signerInfos.0.signature,OCTET STRING,0x1234" \
	"1.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1234" \
	"1.cer,tbsCertificate.signature.parameters,ANY,0x1234" \
	"2.cer,tbsCertificate.signature.parameters,ANY,0x123456" \
	"3.cer,tbsCertificate.signature.parameters,ANY,0x123456" \
	"4.cer,tbsCertificate.signature.parameters,ANY,0x00A100A200A300A400A500A600A700A880B180B280B380B480B580B680B780B8A0C1A0C2A0C3A0C4A0C500C6A0C7A0C8F0D1F0D2F0D3F0D4F0D5F0D6F0D7F0" \
	"4.cer,tbsCertificate.version,INTEGER,0x00000001" \
	"5.cer,tbsCertificate.signature.parameters,ANY,0x00000001" \
	"2.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"3.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"4.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0xF8/6" \
	"5.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"6.cer,tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,BIT STRING,0x1000000000000000000000000000000000" \
	"5.cer,tbsCertificate.version,INTEGER,0x0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

check_output_contains "tutorial-bool" \
	"ta.cer,tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ta.cer,tbsCertificate.extensions.asn.critical,BOOLEAN,true" \
	"ta.cer,tbsCertificate.extensions.ski.critical,BOOLEAN,false"

check_output_contains "tutorial-oid" \
	"roa1.roa,content.encapContentInfo.eContentType,OBJECT IDENTIFIER,1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)"

check_output_contains "tutorial-date" \
	"ta.cer,tbsCertificate.validity.notBefore,Time,2025-07-15T19:39:38Z"

check_output_contains "tutorial-name" \
	"ta.cer,tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ta.cer,tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,ta.cer" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,aaa" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.0.1.type,OBJECT IDENTIFIER,2.5.4.5 (serialNumber)" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.0.1.value,PrintableString in ANY,bbb" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.0.type,OBJECT IDENTIFIER,2.5.4.4 (surname)" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.0.value,PrintableString in ANY,ccc" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.1.type,OBJECT IDENTIFIER,2.5.4.42 (givenName)" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.1.value,PrintableString in ANY,ddd" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.2.type,OBJECT IDENTIFIER,2.5.4.43 (initials)" \
	"ca1.cer,tbsCertificate.subject.rdnSequence.1.2.value,PrintableString in ANY,eee"

check_output_contains "tutorial-ext" \
	"ta.cer,tbsCertificate.extensions,Extensions,\"\[ bc, ski, ku, sia, cp, ip, asn \]\"" \
	"ca1.cer,tbsCertificate.extensions,Extensions,\"\[ bc, ski, aki, ku, crldp, aia, sia, cp, ip, asn \]\"" \
	"roa1.roa,content.certificates.0.tbsCertificate.extensions,Extensions,\"\[ ski, aki, ku, crldp, aia, sia, cp, ip, asn \]\"" \
	"ta.crl,tbsCertList.crlExtensions,Extensions,\"\[ aki, crln \]\"" \
	"ca1.cer,tbsCertificate.extensions.ip.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.28 (sbgp-ipAddrBlockv2)" \
	"ca1.cer,tbsCertificate.extensions.ip.critical,BOOLEAN,true" \
	"ca1.cer,tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate),\"\[ \[ 192.0.2.0/24 \], \[ 2001:db8::/96 \] \]\"" \
	"ca1.cer,tbsCertificate.extensions.asn.extnID,OBJECT IDENTIFIER,1.3.6.1.5.5.7.1.29 (sbgp-autonomousSysNumv2)" \
	"ca1.cer,tbsCertificate.extensions.asn.critical,BOOLEAN,true" \
	"ca1.cer,tbsCertificate.extensions.asn.extnValue.asnum,AS Resources,\"\[ 0x1234, 0x5678 \]\"" \
	"ca1.cer,tbsCertificate.extensions.asn.extnValue.rdi,AS Resources,\"\[ 0x9ABC, 0xDEF0 \]\"" \
	"ca2.cer,tbsCertificate.extensions,Extensions,\"\[ ip, asn \]\"" \
	"ca2.cer,tbsCertificate.extensions.0.extnID,OBJECT IDENTIFIER,1.2.3.4.5" \
	"ca3.cer,tbsCertificate.extensions,Extensions,\"\[ ip, asn, ip, bc, ip, asn \]\"" \
	"ca3.cer,tbsCertificate.extensions.4.extnID,OBJECT IDENTIFIER,1.2.3.4.5"

check_output_contains "tutorial-ip" \
	"roa1.roa,content.encapContentInfo.eContent.ipAddrBlocks,IP Resources (ROA),\"\[ \[ 192.0.2.0/24, 203.0.113.0/32 \], \[ 2001:db8::/40-48 \] \]\""

check_output_contains "root-only-signature" "ta\\.cer,signature,BIT STRING,0x010203"
check_output_contains "root-only" "ta\\.cer,signature,BIT STRING,$HEXNUM"
check_output_contains "root-only-signature-crl" "0\\.crl,signature,BIT STRING,0x010203"
check_output_contains "root-only" "0\\.crl,signature,BIT STRING,$HEXNUM"

FILELIST="content\\.encapContentInfo\\.eContent\\.fileList"
check_output_contains "root-only" \
	"0\\.mft,$FILELIST,File List,{ 0\\.crl=$HEXNUM }" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,0\\.crl" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,$HEXNUM"
check_output_contains "filelist-str" \
	"0\\.mft,$FILELIST,File List,\"{ =0, =0, =0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-str-extra" \
	"0\\.mft,$FILELIST,File List,\"{ =0, fake=0, =0x0102 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,fake" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String," \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x0102"
check_output_contains "filelist-set" \
	"0\\.mft,$FILELIST,File List,\"{ no1=0, 0\\.crl=$HEXNUM, no2=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,no2" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-set-extra" \
	"0\\.mft,$FILELIST,File List,\"{ no1=0x0304, 0\\.crl=$HEXNUM, yes=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x0304" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,yes" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0"
check_output_contains "filelist-map" \
	"0\\.mft,$FILELIST,File List,\"{ a=0x01, b=0x02, c=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0x02" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,c" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x03"
check_output_contains "filelist-map-extra" \
	"0\\.mft,$FILELIST,File List,\"{ a=0x01, b=0x10, ddd=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,IA5String,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,BIT STRING,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,IA5String,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,BIT STRING,0x10" \
	"0\\.mft,$FILELIST\\.2\\.file,IA5String,ddd" \
	"0\\.mft,$FILELIST\\.2\\.hash,BIT STRING,0x03"

check_output_contains "tutorial-filelist-default" \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "tutorial-filelist-default-explicit" \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "tutorial-filelist-crl-omitted" \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=$HEXNUM, B\\.cer=$HEXNUM, 0\\.crl=$HEXNUM }\""
check_output_contains "tutorial-filelist-overrides-isolated" \
	"mft\\.mft,$FILELIST,File List,\"{ crl\\.crl=$HEXNUM, A\\.cer=0x010203, potatoes=0 }\""
check_output_contains "tutorial-filelist-overrides-full" \
	"mft\\.mft,$FILELIST,File List,\"{ A\\.cer=0x010203, nonexistent\\.cer=0x040506, mft\\.mft=0x112233, foobar=0x55555555555555 }\""

check_output_contains "eContent" \
	"0\\.mft,content\\.encapContentInfo\\.eContent,ANY,0xAABBCC"

check_output_contains "obj0" \
	"ta\\.cer,tbsCertificate\\.version,INTEGER,0x04" \
	"ta\\.cer,tbsCertificate\\.serialNumber,INTEGER,0x05" \
	"ta\\.cer,tbsCertificate\\.signature\\.algorithm,OBJECT IDENTIFIER,1\\.2\\.3\\.4" \
	"ta\\.cer,tbsCertificate\\.signature\\.parameters,ANY,0x0607"
check_output_contains "obj1" \
	"ta\\.cer,tbsCertificate\\.version,INTEGER,0x04" \
	"ta\\.cer,tbsCertificate\\.serialNumber,INTEGER,0x05" \
	"ta\\.cer,tbsCertificate\\.signature\\.algorithm,OBJECT IDENTIFIER,1\\.2\\.3\\.4" \
	"ta\\.cer,tbsCertificate\\.signature\\.parameters,ANY,0x0607"
check_output_contains "obj2" \
	"ta\\.cer,tbsCertificate\\.version,INTEGER,0x04" \
	"ta\\.cer,tbsCertificate\\.serialNumber,INTEGER,0x05" \
	"ta\\.cer,tbsCertificate\\.signature\\.algorithm,OBJECT IDENTIFIER,1\\.2\\.3\\.4" \
	"ta\\.cer,tbsCertificate\\.signature\\.parameters,ANY,0x0607"

check_output_contains "notification-1" \
	"https://localhost:8080/rpki/notification-1.xml,path,UTF8String,sandbox/rrdp/notification-1.xml" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.uri,UTF8String,https://localhost:8080/rpki/notification-1.xml.snapshot" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.path,UTF8String,sandbox/rrdp/notification-1.xml.snapshot" \
	"https://localhost:8080/rpki/notification-1.xml,snapshot.files,Snapshot Files,\"\[ 0.crl, 0.mft \]\""
check_output_contains "notification-2" \
	"https://localhost:8080/rpki/notification-2.xml,path,UTF8String,sandbox/rrdp/notification-2.xml" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.uri,UTF8String,https://localhost:8080/rpki/notification-2.xml.snapshot" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.path,UTF8String,sandbox/rrdp/notification-2.xml.snapshot" \
	"https://localhost:8080/rpki/notification-2.xml,snapshot.files,Snapshot Files,\"\[ A.cer, A.roa, 1.crl, B.cer, 2.crl, 0.crl, 1.mft, 2.mft, 0.mft \]\""

echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
