#!/bin/sh

run_barry "keys-preservation-1"
run_barry "keys-preservation-2"

KEYS1="sandbox/output/keys-preservation-1"
KEYS2="sandbox/output/keys-preservation-2"

grep -F "subjectPublicKey,BIT STRING" "$KEYS1.log" > "$KEYS1"
grep -F "subjectPublicKey,BIT STRING" "$KEYS2.log" > "$KEYS2"

DIFFS="$(sort "$KEYS1" "$KEYS2" | uniq -u | wc -l)"
if [ "$DIFFS" -eq 1 ]; then
	SUCCESSES=$((SUCCESSES+1))
else
	echo "ERR: Expected 1 different key, got $DIFFS."
	echo "ERR: See \"diff $KEYS1 $KEYS2\"."
	FAILS=$((FAILS+1))
fi
