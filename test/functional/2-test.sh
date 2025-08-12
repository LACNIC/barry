#!/bin/sh

# We normally want to test the latest patch; compile that.
cd ../..
make > /dev/null
cd test/functional

# Prepare test sandbox
mkdir -p sandbox/keys
mkdir -p sandbox/output
mkdir -p sandbox/rsync
mkdir -p sandbox/tal

if [ -z "$(ls -A sandbox/keys)" ]; then		# "If sandbox/keys is empty"
	for i in $(seq 0 10); do
		echo "Creating sandbox/keys/$i.pem"
		openssl genrsa -out "sandbox/keys/$i.pem" 2048
	done
fi

# Prepare common barry arguments, needed by all tests
BARRY="../../src/barry"
RSYNC_PATH="--rsync-path sandbox/rsync"
KEYS="--keys sandbox/keys"
PRINTS="-p csv"
TIMES="--now 2025-01-01T00:00:00Z --later 2026-01-01T00:00:00Z"
BASIC_ARGS="$RSYNC_PATH $KEYS $PRINTS $TIMES"

# Cache default outputs.
# (Several tests want to compare their outputs to these.)
$BARRY $BASIC_ARGS --tal-path sandbox/tal/root-only.tal rd/root-only.rd > sandbox/output/root-only.csv

# Test procedure
check_single_override() {
	# $1: Test RD filename, without extension
	TEST_RD="$1"
	# $2: Default output CSV filename, without extension
	DEFAULT_CSV="$2"
	# $3: Line of text that should be present in the test output,
	# and absent from the default output.
	EXPECTED_OUTPUT="$3"

	$BARRY $BASIC_ARGS --tal-path "sandbox/tal/$TEST_RD.tal" "rd/$TEST_RD.rd" | grep -Fx "$EXPECTED_OUTPUT" > /dev/null
	if [ $? -eq 0 ]; then
		SUCCESSES=$((SUCCESSES+1))
	else
		echo "ERR: Test '$TEST_RD' did not output '$EXPECTED_OUTPUT'."
		FAILS=$((FAILS+1))
	fi

	grep -Fx "$EXPECTED_OUTPUT" < "sandbox/output/$DEFAULT_CSV.csv" > /dev/null
	if [ $? -ne 0 ]; then
		SUCCESSES=$((SUCCESSES+1))
	else
		echo "ERR: Default output '$DEFAULT_CSV' contains '$EXPECTED_OUTPUT'."
		FAILS=$((FAILS+1))
	fi
}

SUCCESSES=0
FAILS=0

check_single_override root-only-signature root-only "ta.cer,signature,0x010203"
check_single_override root-only-signature-crl root-only "0.crl,signature,0x010203"

echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
