#!/bin/sh

# Also tests --serial.

STEP1_NOW="2025-01-01T00:00:00Z"
STEP1_LATER="2025-02-01T00:00:00Z"

STEP2_NOW="2026-01-01T00:00:00Z"
STEP2_LATER="2026-02-01T00:00:00Z"

STEP3_NOW="2027-01-01T00:00:00Z"
STEP3_LATER="2027-02-01T00:00:00Z"

check_preserved() {
	diff "sandbox/rsync/shield$1/$3" "sandbox/rsync/shield$2/$3"
	check_result "$?" "$3 was not preserved."
}

# Step 1

run_barry "shield1" --now "$STEP1_NOW" --later "$STEP1_LATER" --serial 10
check_output_contains "shield1" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,$STEP1_NOW" \
	"ta.cer,obj.tbsCertificate.validity.notAfter,Time,$STEP1_LATER" \
	"R.roa,obj.content.certificates.0.tbsCertificate.validity.notBefore,Time,$STEP1_NOW" \
	"R.roa,obj.content.certificates.0.tbsCertificate.validity.notAfter,Time,$STEP1_LATER" \
	"C.crl,obj.tbsCertList.thisUpdate,Time,$STEP1_NOW" \
	"C.crl,obj.tbsCertList.nextUpdate,Time,$STEP1_LATER" \
	"M.mft,obj.content.encapContentInfo.eContent.manifestNumber,INTEGER,0x0A" \
	"M.mft,obj.content.encapContentInfo.eContent.thisUpdate,GeneralizedTime,$STEP1_NOW" \
	"M.mft,obj.content.encapContentInfo.eContent.nextUpdate,GeneralizedTime,$STEP1_LATER" \
	"M.mft,obj.content.certificates.0.tbsCertificate.validity.notBefore,Time,$STEP1_NOW" \
	"M.mft,obj.content.certificates.0.tbsCertificate.validity.notAfter,Time,$STEP1_LATER" \
	"https://localhost:8443/rrdp/notification.xml,serial,INTEGER,0x0A"

# Step 2

run_barry "shield2" --now "$STEP2_NOW" --later "$STEP2_LATER" \
	--serial 20 --previous-path "sandbox/rsync/shield1"
check_output_contains "shield2" -Fx \
	"ta.cer,obj.tbsCertificate.validity.notBefore,Time,$STEP2_NOW" \
	"ta.cer,obj.tbsCertificate.validity.notAfter,Time,$STEP2_LATER" \
	"C.crl,obj.tbsCertList.thisUpdate,Time,$STEP2_NOW" \
	"C.crl,obj.tbsCertList.nextUpdate,Time,$STEP2_LATER" \
	"M.mft,obj.content.encapContentInfo.eContent.manifestNumber,INTEGER,0x14" \
	"M.mft,obj.content.encapContentInfo.eContent.thisUpdate,GeneralizedTime,$STEP2_NOW" \
	"M.mft,obj.content.encapContentInfo.eContent.nextUpdate,GeneralizedTime,$STEP2_LATER" \
	"M.mft,obj.content.certificates.0.tbsCertificate.validity.notBefore,Time,$STEP2_NOW" \
	"M.mft,obj.content.certificates.0.tbsCertificate.validity.notAfter,Time,$STEP2_LATER" \
	"https://localhost:8443/rrdp/notification.xml,serial,INTEGER,0x14"

check_preserved 1 2 "ta/R.roa"

# Step 3

run_barry "shield3" --now "$STEP3_NOW" --later "$STEP3_LATER" \
	--serial 30 --previous-path "sandbox/rsync/shield2"
check_output_contains "shield3" -Fx \
	"R.roa,obj.content.certificates.0.tbsCertificate.validity.notBefore,Time,$STEP3_NOW" \
	"R.roa,obj.content.certificates.0.tbsCertificate.validity.notAfter,Time,$STEP3_LATER" \
	"https://localhost:8443/rrdp/notification.xml,serial,INTEGER,0x1E"

check_preserved 2 3 "ta.cer"
check_preserved 2 3 "ta/A.asa"
check_preserved 2 3 "ta/C.crl"
check_preserved 2 3 "ta/M.mft"
