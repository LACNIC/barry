#!/bin/sh

# We normally want to test the latest patch; compile that.
cd ../..
make > /dev/null
cd "test/functional"

# Prepare test sandbox
mkdir -p "sandbox/keys"
mkdir -p "sandbox/output"
mkdir -p "sandbox/rsync"
mkdir -p "sandbox/tal"

if [ -z "$(ls -A sandbox/keys)" ]; then    # "If sandbox/keys is empty"
	for i in $(seq 0 10); do
		echo "Creating sandbox/keys/$i.pem"
		openssl genrsa -out "sandbox/keys/$i.pem" 2048
	done
fi

rm -rf sandbox/output/*
rm -rf sandbox/rsync/*
rm -rf sandbox/tal/*

# Prepare common barry arguments, needed by all tests
BARRY="../../src/barry"
RSYNC_PATH="--rsync-path sandbox/rsync"
KEYS="--keys sandbox/keys"
PRINTS="-vvp csv"
TIMES="--now 2025-01-01T00:00:00Z --later 2026-01-01T00:00:00Z"
BASIC_ARGS="$RSYNC_PATH $KEYS $PRINTS $TIMES"

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

check_output_contains "root-only-signature" "ta\\.cer,signature,0x010203"
check_output_contains "root-only" "ta\\.cer,signature,$HEXNUM"
check_output_contains "root-only-signature-crl" "0\\.crl,signature,0x010203"
check_output_contains "root-only" "0\\.crl,signature,$HEXNUM"

FILELIST="content\\.encapContentInfo\\.eContent\\.fileList"
check_output_contains "root-only" \
	"0\\.mft,$FILELIST,{ 0\\.crl=$HEXNUM }" \
	"0\\.mft,$FILELIST\\.0\\.file,0\\.crl" \
	"0\\.mft,$FILELIST\\.0\\.hash,$HEXNUM"
check_output_contains "filelist-str" \
	"0\\.mft,$FILELIST,\"{ =0, =0, =0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file," \
	"0\\.mft,$FILELIST\\.0\\.hash,0" \
	"0\\.mft,$FILELIST\\.1\\.file," \
	"0\\.mft,$FILELIST\\.1\\.hash,0" \
	"0\\.mft,$FILELIST\\.2\\.file," \
	"0\\.mft,$FILELIST\\.2\\.hash,0"
check_output_contains "filelist-str-extra" \
	"0\\.mft,$FILELIST,\"{ =0, fake=0, =0x0102 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file," \
	"0\\.mft,$FILELIST\\.0\\.hash,0" \
	"0\\.mft,$FILELIST\\.1\\.file,fake" \
	"0\\.mft,$FILELIST\\.1\\.hash,0" \
	"0\\.mft,$FILELIST\\.2\\.file," \
	"0\\.mft,$FILELIST\\.2\\.hash,0x0102"
check_output_contains "filelist-set" \
	"0\\.mft,$FILELIST,\"{ no1=0, 0\\.crl=$HEXNUM, no2=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,0" \
	"0\\.mft,$FILELIST\\.1\\.file,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,no2" \
	"0\\.mft,$FILELIST\\.2\\.hash,0"
check_output_contains "filelist-set-extra" \
	"0\\.mft,$FILELIST,\"{ no1=0x0304, 0\\.crl=$HEXNUM, yes=0 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,no1" \
	"0\\.mft,$FILELIST\\.0\\.hash,0x0304" \
	"0\\.mft,$FILELIST\\.1\\.file,0\\.crl" \
	"0\\.mft,$FILELIST\\.1\\.hash,$HEXNUM" \
	"0\\.mft,$FILELIST\\.2\\.file,yes" \
	"0\\.mft,$FILELIST\\.2\\.hash,0"
check_output_contains "filelist-map" \
	"0\\.mft,$FILELIST,\"{ a=0x01, b=0x02, c=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,0x02" \
	"0\\.mft,$FILELIST\\.2\\.file,c" \
	"0\\.mft,$FILELIST\\.2\\.hash,0x03"
check_output_contains "filelist-map-extra" \
	"0\\.mft,$FILELIST,\"{ a=0x01, b=0x10, ddd=0x03 }\"" \
	"0\\.mft,$FILELIST\\.0\\.file,a" \
	"0\\.mft,$FILELIST\\.0\\.hash,0x01" \
	"0\\.mft,$FILELIST\\.1\\.file,b" \
	"0\\.mft,$FILELIST\\.1\\.hash,0x10" \
	"0\\.mft,$FILELIST\\.2\\.file,ddd" \
	"0\\.mft,$FILELIST\\.2\\.hash,0x03"

check_output_contains "filelist-tutorial-default" \
	"mft\\.mft,$FILELIST,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "filelist-tutorial-default-explicit" \
	"mft\\.mft,$FILELIST,\"{ crl\\.crl=$HEXNUM, A\\.cer=$HEXNUM, B\\.cer=$HEXNUM }\""
check_output_contains "filelist-tutorial-crl-omitted" \
	"mft\\.mft,$FILELIST,\"{ A\\.cer=$HEXNUM, B\\.cer=$HEXNUM, 0\\.crl=$HEXNUM }\""
check_output_contains "filelist-tutorial-overrides-isolated" \
	"mft\\.mft,$FILELIST,\"{ crl\\.crl=$HEXNUM, A\\.cer=0x010203, potatoes=0 }\""
check_output_contains "filelist-tutorial-overrides-full" \
	"mft\\.mft,$FILELIST,\"{ A\\.cer=0x010203, nonexistent\\.cer=0x040506, mft\\.mft=0x112233, foobar=0x55555555555555 }\""

echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
