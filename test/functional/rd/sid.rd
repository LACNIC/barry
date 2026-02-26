ta.cer
	default.roa
	issuerAndSerial-self.roa
	issuerAndSerial-children.roa
	ski.roa

[node: issuerAndSerial-self.roa]
obj.content.signerInfos.0.sid.issuerAndSerialNumber = {
	issuer.rdnSequence = [[{
		type = 2.5.4.3,    # commonName
		value = issuer1
	}]],
	serialNumber = 0x111111,
}

[node: issuerAndSerial-children.roa]
obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence = [[{
	type = 2.5.4.3,    # commonName
	value = issuer2
}]]
obj.content.signerInfos.0.sid.issuerAndSerialNumber.serialNumber = 0x222222

[node: ski.roa]
obj.content.signerInfos.0.sid.subjectKeyIdentifier = 0x551177
