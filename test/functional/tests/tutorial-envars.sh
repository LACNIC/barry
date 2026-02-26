#!/bin/sh

export TA_NAME="root.cer"
export CA_NAME="aaaa.cer"
export ROA_NAME="aor.roa"
export OID_KEY="obj.content.encapContentInfo.eContentType"
export OID_VALUE="1.2.840.113549.1.9.16.1.26"
export SUBJECT="LACNIC"
export ISSUANCE_DATE="$(date +%Y-%m-%dT%H:%M:%SZ)"
export TBSCER="tbsCertificate"
export TBS="tbs"

check_output_contains "tutorial-envars" -Fx \
	"root.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,$SUBJECT" \
	"root.cer,obj.$TBSCER.validity.notBefore,Time,$ISSUANCE_DATE" \
	'aaaa.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,Te$t' \
	"$ROA_NAME,$OID_KEY,OBJECT IDENTIFIER,$OID_VALUE (id-ct-rpkiManifest)"
