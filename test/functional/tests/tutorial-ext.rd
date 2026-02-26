ta.cer
	ca1.cer
	ca2.cer
	ca3.cer
	roa1.roa
	ta.crl

[node: ca1.cer]
obj.tbsCertificate.extensions.ip.extnID = 1.3.6.1.5.5.7.1.28
obj.tbsCertificate.extensions.ip.critical = true
obj.tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24, 2001:db8::/96 ]
obj.tbsCertificate.extensions.as.extnID = 1.3.6.1.5.5.7.1.29
obj.tbsCertificate.extensions.as.critical = true
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x1234, 0x5678 ]
obj.tbsCertificate.extensions.as.extnValue.rdi = [ 0x9ABC, 0xDEF0 ]

[node: ca2.cer]
obj.tbsCertificate.extensions = [ ip, as ]
obj.tbsCertificate.extensions.ip.extnID = 1.2.3.4.5

[node: ca3.cer]
obj.tbsCertificate.extensions = {
	red = ip,
	blue = as,
	yellow = ip,
	purple = bc,
	orange = ip,
	green = as
}
obj.tbsCertificate.extensions.orange.extnID = 1.2.3.4.5
