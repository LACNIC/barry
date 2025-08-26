ta.cer
	A.cer
	B.mft
	C.crl

[node: A.cer]

obj.tbsCertificate.extensions.sia.extnValue.0 = { # default SIA[0]: caRepository
	accessMethod = 1.2.3.4,
	accessLocation.type = registeredID,
	accessLocation.value = 1.2.4.6,
}

obj.tbsCertificate.extensions.sia.extnValue.1 = { # default SIA[1]: rpkiManifest
	accessLocation.type = iPAddress,
}

obj.tbsCertificate.extensions.sia.extnValue.2 = { # default SIA[2]: rpkiNotify
	accessLocation.value = https://aaaaaa
}

obj.tbsCertificate.extensions.aia.extnValue.0 = { # default AIA[0]: caIssuers
	accessLocation.value = rsync://bbbbbb
}

[node: B.mft]

# default SIA[0]: signedObject
obj.content.certificates.0.tbsCertificate.extensions.sia.extnValue.0 = {
	accessMethod = 1.2.840.113549.1.1.11
}

# default AIA[0]: caIssuers
obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue.0 = {
	accessMethod = 2.16.840.1.101.3.4.2.1
}
