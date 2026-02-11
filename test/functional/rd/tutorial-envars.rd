$TA_NAME
	$CA_NAME
		"${ROA_NAME}"

[node: "${TA_NAME}"]
obj.tbsCertificate.subject.rdnSequence.0.0.value = $SUBJECT
obj.$TBSCER.validity.notBefore = $ISSUANCE_DATE

[node: "$CA_NAME"]
"obj.${TBS}Certificate.subject.rdnSequence.0.0.value" = Te$$t

[node: $ROA_NAME]
"${OID_KEY}" = $OID_VALUE
