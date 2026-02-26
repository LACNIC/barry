#!/bin/sh

check_output_contains "sid" \
	"default\\.roa,obj\\.content\\.signerInfos\\.0\\.sid\\.subjectKeyIdentifier,OCTET STRING,$HEXNUM"

check_output_contains "sid" -Fx \
	"default.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence,RDN Sequence,NULL" \
	"default.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.serialNumber,INTEGER,NULL" \
	"issuerAndSerial-self.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence,RDN Sequence,[ [ { \"2.5.4.3 (commonName)\": \"issuer1\" } ] ]" \
	"issuerAndSerial-self.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"issuerAndSerial-self.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence.0.0.value,PrintableString in ANY,issuer1" \
	"issuerAndSerial-self.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.serialNumber,INTEGER,0x111111" \
	"issuerAndSerial-self.roa,obj.content.signerInfos.0.sid.subjectKeyIdentifier,OCTET STRING,NULL" \
	"issuerAndSerial-children.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence,RDN Sequence,[ [ { \"2.5.4.3 (commonName)\": \"issuer2\" } ] ]" \
	"issuerAndSerial-children.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"issuerAndSerial-children.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence.0.0.value,PrintableString in ANY,issuer2" \
	"issuerAndSerial-children.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.serialNumber,INTEGER,0x222222" \
	"issuerAndSerial-children.roa,obj.content.signerInfos.0.sid.subjectKeyIdentifier,OCTET STRING,NULL" \
	"ski.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.issuer.rdnSequence,RDN Sequence,NULL" \
	"ski.roa,obj.content.signerInfos.0.sid.issuerAndSerialNumber.serialNumber,INTEGER,NULL" \
	"ski.roa,obj.content.signerInfos.0.sid.subjectKeyIdentifier,OCTET STRING,0x551177"
