#!/bin/sh

# If $1 exists, only the matching test script will be run.

fail() {
	echo "$1"
	exit 1
}

# We always want to test the latest patch; compile that.
cd ../..
make > /dev/null || fail "Barry could not be compiled."
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
KEYS="--keys sandbox/keys"
PRINTS="-cvvp csv"
TIMES="--now 2025-01-01T00:00:00Z --later 2026-01-01T00:00:00Z"
BASIC_ARGS="$KEYS $PRINTS $TIMES"

# Cache default outputs.
# (Several tests want to compare their outputs to these.)
DEFAULT_OUTPUT_FILE="sandbox/output/root-only.log"
$BARRY $BASIC_ARGS						\
	--tal-path "sandbox/tal/root-only.tal"			\
	--rsync-path "sandbox/rsync/root-only"			\
	--rrdp-path "sandbox/rrdp/root-only"			\
	"tests/root-only.rd"					\
	> "$DEFAULT_OUTPUT_FILE" 2>&1

check_output_contains() {
	# $1: Test RD filename, without extension
	TEST_RD="$1"
	# $2: Arguments to grep
	GREP_ARGS="$2"
	# $3-$n: Regular expression that describes the line that should be
	# present in the test output

	OUTPUT_FILE="sandbox/output/$TEST_RD.log"
	if [ ! -f "$OUTPUT_FILE" ]; then
		$BARRY $BASIC_ARGS				\
			--tal-path "sandbox/tal/$TEST_RD.tal"	\
			--rsync-path "sandbox/rsync/$TEST_RD"	\
			--rrdp-path "sandbox/rrdp/$TEST_RD"	\
			"tests/$TEST_RD.rd"			\
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

SUCCESSES=0
FAILS=0

HEXNUM="0x[0-9A-F][0-9A-F]*"


if [ -z "$1" ]; then
	for TEST in tests/*.sh; do
		. "./$TEST"
	done
else
	. "./tests/$1.sh"
fi


echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
