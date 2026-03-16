ta.cer
	a.roa
	a.asa
	a.mft
	4-only.cer
		4-only.mft
	6-only.cer
		6-only.mft
	more.cer
		1.roa
		2.roa
		3.roa
		1.asa
		2.asa
		3.asa

[node: 4-only.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 4.4.0.0/24 ]

[node: 6-only.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 6.6.0.0/24 ]
