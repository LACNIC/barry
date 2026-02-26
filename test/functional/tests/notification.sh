#!/bin/sh

check_output_contains "notification-1" -Fx \
	"https://localhost:8443/rrdp/notification-1.xml,path,C String,notification-1.xml" \
	"https://localhost:8443/rrdp/notification-1.xml,snapshot.uri,C String,https://localhost:8443/rrdp/notification-1.xml.snapshot" \
	"https://localhost:8443/rrdp/notification-1.xml,snapshot.path,C String,notification-1.xml.snapshot" \
	"https://localhost:8443/rrdp/notification-1.xml,snapshot.files,Snapshot Files,\"[ ta.mft, ta.crl ]\""

check_output_contains "notification-2" -Fx \
	"https://localhost:8443/rrdp/notification-2.xml,path,C String,notification-2.xml" \
	"https://localhost:8443/rrdp/notification-2.xml,snapshot.uri,C String,https://localhost:8443/rrdp/notification-2.xml.snapshot" \
	"https://localhost:8443/rrdp/notification-2.xml,snapshot.path,C String,notification-2.xml.snapshot" \
	"https://localhost:8443/rrdp/notification-2.xml,snapshot.files,Snapshot Files,\"[ A.cer, A.roa, A.mft, A.crl, B.cer, B.mft, B.crl, ta.mft, ta.crl ]\""
