ta.cer
	ca1.cer
	ca2.cer
	ca3.cer
	roa1.roa
	ta.crl

[ca1.cer]
tbsCertificate.extensions.ip.extnID = 1.3.6.1.5.5.7.1.28
tbsCertificate.extensions.ip.critical = true
tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24, 2001:db8::/96 ]
tbsCertificate.extensions.asn.extnID = 1.3.6.1.5.5.7.1.29
tbsCertificate.extensions.asn.critical = true
tbsCertificate.extensions.asn.extnValue.asnum = [ 0x1234, 0x5678 ]
tbsCertificate.extensions.asn.extnValue.rdi = [ 0x9ABC, 0xDEF0 ]

[ca2.cer]
tbsCertificate.extensions.ip.extnID = 1.2.3.4.5
tbsCertificate.extensions = [ ip, asn ]
tbsCertificate.extensions.ip.extnID = 1.2.3.4.5

[ca3.cer]
tbsCertificate.extensions = [ ip, asn, ip, bc, ip, asn ]
tbsCertificate.extensions.4.extnID = 1.2.3.4.5
