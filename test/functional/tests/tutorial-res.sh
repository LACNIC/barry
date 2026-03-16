#!/bin/sh

CIP="obj.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate)"
CAS="obj.tbsCertificate.extensions.as.extnValue.asnum,AS Resources"

EIP="obj.content.certificates.0.tbsCertificate.extensions.ip.extnValue,IP Resources (Certificate)"
EAS="obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum,AS Resources"

check_output_contains "tutorial-res-override" -Fx \
	"TA0.cer,$CIP,\"[ [ 0.0.0.0/0 ], [ ::/0 ] ]\"" \
	"CA1.cer,$CIP,\"[ [ 1.0.0.0/8 ], [ 100::/8 ] ]\"" \
	"CA2.cer,$CIP,[ [ 6.6.6.0/24 ] ]" \
	"CA3.cer,$CIP,[ [ 6.6.6.0/24 ] ]" \
	"CA4.cer,$CIP,[ [ 6.6.6.0/24 ] ]" \
	"TA0.cer,$CAS,[ 0x00-0x00FFFFFFFF ]" \
	"CA1.cer,$CAS,[ 0x01000000-0x01FFFFFF ]" \
	"CA2.cer,$CAS,[ 0x06060600-0x060606FF ]" \
	"CA3.cer,$CAS,[ 0x06060600-0x060606FF ]" \
	"CA4.cer,$CAS,[ 0x06060600-0x060606FF ]" \
	"no-ip.roa,$EIP,\"[ [ 2.1.0.0/16 ], [ 201::/16 ] ]\"" \
	"no-as.asa,$EAS,[ 0x03010000 ]" \
	"as.roa,$EAS,[ 0x04000000-0x04FFFFFF ]" \
	"ip.asa,$EIP,\"[ [ 5.0.0.0/8 ], [ 500::/8 ] ]\""

check_output_contains "tutorial-res-ee" -Fx \
	"a.roa,$EIP,\"[ [ 1.0.0.0/8 ], [ 100::/8 ] ]\"" \
	"a.asa,$EAS,[ 0x02000000 ]" \
	"a.mft,$EIP,\"[ [ 3.0.0.0/8 ], [ 300::/8 ] ]\"" \
	"a.mft,$EAS,[ 0x03000000-0x03FFFFFF ]" \
	"4-only.mft,$EIP,[ [ 4.4.0.0/24 ] ]" \
	"6-only.mft,$EIP,[ [ 6.6.0.0/24 ] ]" \
	"1.roa,$EIP,\"[ [ 6.1.0.0/16 ], [ 601::/16 ] ]\"" \
	"2.roa,$EIP,\"[ [ 6.2.0.0/16 ], [ 602::/16 ] ]\"" \
	"3.roa,$EIP,\"[ [ 6.3.0.0/16 ], [ 603::/16 ] ]\"" \
	"1.asa,$EAS,[ 0x06040000 ]" \
	"2.asa,$EAS,[ 0x06050000 ]" \
	"3.asa,$EAS,[ 0x06060000 ]"
