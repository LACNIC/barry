ta.cer
	A.cer
	B.mft
	C.crl

[node: A.cer]
tbsCertificate.extensions = [ aia, sia ]

[node: B.mft]
content.certificates.0.tbsCertificate.extensions = [ aia, sia ]

[node: C.crl]
tbsCertList.crlExtensions = [ aia, sia ]
