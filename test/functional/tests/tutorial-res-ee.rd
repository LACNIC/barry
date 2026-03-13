ta.cer
	a.roa
	a.asa
	a.mft
	4-only.cer
		4-only.mft
	6-only.cer
		6-only.mft

[node: 4-only.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 4.4.0.0/24 ]

[node: 6-only.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 6.6.0.0/24 ]
