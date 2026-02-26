ta.cer
	roa.roa
		certificate.cer
	crl.crl
	manifest.mft

[node: roa.roa]
type = cer

[node: certificate.cer]
type = roa

[node: crl.crl]
type = mft

[node: manifest.mft]
type = crl
