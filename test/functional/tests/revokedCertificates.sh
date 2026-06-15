#!/bin/sh

check_output_contains "revokedCertificates" -Fx "ta.crl,obj.tbsCertList.revokedCertificates,Revoked Certificates,[ 0xEE0001 ]"
