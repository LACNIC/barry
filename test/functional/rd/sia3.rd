ta.cer
	A.cer
	B.mft
	C.crl

[node: A.cer]
obj.tbsCertificate.extensions = [ aia, sia ]

[node: B.mft]
obj.content.certificates.0.tbsCertificate.extensions = [ aia, sia ]

[node: C.crl]
obj.tbsCertList.crlExtensions = [ aia, sia ]
