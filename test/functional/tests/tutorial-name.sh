#!/bin/sh

check_output_contains "tutorial-name" -Fx \
	"ta.cer,obj.tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ta.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,ta.cer" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.0.type,OBJECT IDENTIFIER,2.5.4.3 (commonName)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.0.value,PrintableString in ANY,aaa" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.1.type,OBJECT IDENTIFIER,2.5.4.5 (serialNumber)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.0.1.value,PrintableString in ANY,bbb" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.0.type,OBJECT IDENTIFIER,2.5.4.4 (surname)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.0.value,PrintableString in ANY,ccc" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.1.type,OBJECT IDENTIFIER,2.5.4.42 (givenName)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.1.value,PrintableString in ANY,ddd" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.2.type,OBJECT IDENTIFIER,2.5.4.43 (initials)" \
	"ca1.cer,obj.tbsCertificate.subject.rdnSequence.1.2.value,PrintableString in ANY,eee"
