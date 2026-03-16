TA0.cer
	CA1.cer
		CA2.cer
			CA3.cer
				CA4.cer

	no-ip.cer
		# Parent does not define an IP extension,
		# so this one can't inherit anything.
		# There's nothing this ROA can do to be correct,
		# so it falls back to default resource assignment.
		# Which isn't supposed to validate;
		# we're mainly just testing Barry doesn't crash.
		no-ip.roa
	no-as.cer
		# AS counterpart of no-ip.roa.
		no-as.asa

	# Has an AS extension but no IP extension.
	# Also nonsense, also falls back to default resource assignment.
	# Also mainly testing no crash.
	as.roa
	# IP counterpart of as.roa.
	ip.asa

[node: CA2.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 6.6.6.0/24 ]
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x06060600-0x060606FF ]

[node: no-ip.cer]
obj.tbsCertificate.extensions = [ bc, ski, aki, ku, cdp, aia, sia, cp, as ]

[node: no-as.cer]
obj.tbsCertificate.extensions = [ bc, ski, aki, ku, cdp, aia, sia, cp, ip ]

[node: as.roa]
obj.content.certificates.0.tbsCertificate.extensions = [
	ski, aki, ku, cdp, aia, sia, cp, as
]

[node: ip.asa]
obj.content.certificates.0.tbsCertificate.extensions = [
	ski, aki, ku, cdp, aia, sia, cp, ip
]
