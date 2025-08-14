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
	# $2-$n: Text line that should be present in the test output

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
		grep -Fx "$1" "$OUTPUT_FILE" > /dev/null
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

check_output_contains "root-only-signature" "ta.cer,signature,0x010203"
check_output_contains "root-only" "ta.cer,signature,0x03B90389A47C71BCA2B566FEAB5DF4304FD5FB9AC9BDF4CEF9212F4F10D115DF2B3B06BC9D04679600CE9ECB2EF2E294AE1E00C9D1F5E87F193F1566FCD02EAE9811AC5C8AC8B27FC5BE89720B70DEA00C67D3C3AC96DE3BA985D500BDCE349634130C6F55FF62D673C82645698C8DD2484FABFAD21CDAFEC6FC036153C616FFA9C1A21CF35FAF8FDF0A4F5648362197F3704E009C4D8DCEFA28149254AE8C0E4F2BB3293FDF50F938D08C9D585D677F51F2EF8C7077B8FA7485E41087971BCC20E099E85AB354376742142C5CA81A024F4E7542A3FFD05CC45CBE7FDD495A4BCCE83D2951F196DA7C86FD652503DE2D0A91A74B3E292CE66906C4CF485318DD"
check_output_contains "root-only-signature-crl" "0.crl,signature,0x010203"
check_output_contains "root-only" "0.crl,signature,0x3D696D89320ED96BD14408698AD22BE97F041E6DA7B0EC0F5AC181BB7A65F9EFFFDA7C3B0356BB62A35B0BBACCFC43AC88FE809C171190E48F300007CBB3EDF8940DA19E0F651BAB78A38DF01263846ADEF1AED267E1B266AD5E497120526FE04E6B0A37C9EBDA57F68FE6D9D096765854F2E722FD0A627DF0ED06BAE077E2B1B13E4FDC7B64833D600FE5E0B6C018F6EFB37F48C9C5C4DA5E2A11E752761D389235A5531C9C5CCB470387188ADA6E8E13D02F8B6F3611B73EB3FD1CC659A998EACFDC652D4204AA1C4724AB89D4457D9A2D145FE4651088A120F029CA5670E5E4097FAC2F61F997A2BBE10BB9461FDFE393273FCC13FD761D873825A4E6CAF8"

FILELIST="content.encapContentInfo.eContent.fileList"
CRL_HASH="0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41"
check_output_contains "root-only" \
	"0.mft,$FILELIST,{ 0.crl=$CRL_HASH }" \
	"0.mft,$FILELIST.0.file,0.crl" \
	"0.mft,$FILELIST.0.hash,$CRL_HASH"
check_output_contains "filelist-str" \
	"0.mft,$FILELIST,\"{ =0, =0, =0 }\"" \
	"0.mft,$FILELIST.0.file," \
	"0.mft,$FILELIST.0.hash,0" \
	"0.mft,$FILELIST.1.file," \
	"0.mft,$FILELIST.1.hash,0" \
	"0.mft,$FILELIST.2.file," \
	"0.mft,$FILELIST.2.hash,0"
check_output_contains "filelist-str-extra" \
	"0.mft,$FILELIST,\"{ =0, fake=0, =0x0102 }\"" \
	"0.mft,$FILELIST.0.file," \
	"0.mft,$FILELIST.0.hash,0" \
	"0.mft,$FILELIST.1.file,fake" \
	"0.mft,$FILELIST.1.hash,0" \
	"0.mft,$FILELIST.2.file," \
	"0.mft,$FILELIST.2.hash,0x0102"
check_output_contains "filelist-set" \
	"0.mft,$FILELIST,\"{ no1=0, 0.crl=$CRL_HASH, no2=0 }\"" \
	"0.mft,$FILELIST.0.file,no1" \
	"0.mft,$FILELIST.0.hash,0" \
	"0.mft,$FILELIST.1.file,0.crl" \
	"0.mft,$FILELIST.1.hash,$CRL_HASH" \
	"0.mft,$FILELIST.2.file,no2" \
	"0.mft,$FILELIST.2.hash,0"
check_output_contains "filelist-set-extra" \
	"0.mft,$FILELIST,\"{ no1=0x0304, 0.crl=$CRL_HASH, yes=0 }\"" \
	"0.mft,$FILELIST.0.file,no1" \
	"0.mft,$FILELIST.0.hash,0x0304" \
	"0.mft,$FILELIST.1.file,0.crl" \
	"0.mft,$FILELIST.1.hash,$CRL_HASH" \
	"0.mft,$FILELIST.2.file,yes" \
	"0.mft,$FILELIST.2.hash,0"
check_output_contains "filelist-map" \
	"0.mft,$FILELIST,\"{ a=0x01, b=0x02, c=0x03 }\"" \
	"0.mft,$FILELIST.0.file,a" \
	"0.mft,$FILELIST.0.hash,0x01" \
	"0.mft,$FILELIST.1.file,b" \
	"0.mft,$FILELIST.1.hash,0x02" \
	"0.mft,$FILELIST.2.file,c" \
	"0.mft,$FILELIST.2.hash,0x03"
check_output_contains "filelist-map-extra" \
	"0.mft,$FILELIST,\"{ a=0x01, b=0x10, ddd=0x03 }\"" \
	"0.mft,$FILELIST.0.file,a" \
	"0.mft,$FILELIST.0.hash,0x01" \
	"0.mft,$FILELIST.1.file,b" \
	"0.mft,$FILELIST.1.hash,0x10" \
	"0.mft,$FILELIST.2.file,ddd" \
	"0.mft,$FILELIST.2.hash,0x03"

check_output_contains "filelist-tutorial-default" \
	"mft.mft,$FILELIST,\"{ crl.crl=0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41, A.cer=0x5EBFE949DAB77A1AED18BC7EDE86C0F4CC784A2227385E6F04461EE85BD7F2C9, B.cer=0x237FF39E12A09160CC2B365BB155D72A25E1CF9073CD583AADAA35E2872AD104 }\""
check_output_contains "filelist-tutorial-default-explicit" \
	"mft.mft,$FILELIST,\"{ crl.crl=0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41, A.cer=0x5EBFE949DAB77A1AED18BC7EDE86C0F4CC784A2227385E6F04461EE85BD7F2C9, B.cer=0x237FF39E12A09160CC2B365BB155D72A25E1CF9073CD583AADAA35E2872AD104 }\""
check_output_contains "filelist-tutorial-crl-omitted" \
	"mft.mft,$FILELIST,\"{ A.cer=0x20F2D9A6844492AD4319786B79299B6DEA00BCD5A7A95E23D2E023D40ADE439C, B.cer=0x00B542C13C1D19C9424D865B16337A6DA24462199B919553581E29D618479A0A, 0.crl=0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41 }\""
check_output_contains "filelist-tutorial-overrides-isolated" \
	"mft.mft,$FILELIST,\"{ crl.crl=0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41, A.cer=0x010203, potatoes=0 }\""
check_output_contains "filelist-tutorial-overrides-full" \
	"mft.mft,$FILELIST,\"{ A.cer=0x010203, nonexistent.cer=0x040506, mft.mft=0x112233, foobar=0x55555555555555 }\""

echo "Successes: $SUCCESSES"
echo "Failures : $FAILS"
