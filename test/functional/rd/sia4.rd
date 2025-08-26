ta.cer
	A.cer
	B.mft
	C.crl

[node: A.cer]
obj.tbsCertificate.extensions = {
	aia1=aia, sia1=sia, sia2=sia, aia2=aia
}
obj.tbsCertificate.extensions.aia1.extnValue = [
	# Access method with default value for certificate AIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.2 }, # caIssuers
	# Access method with no default value for certificate AIAs 
	{ accessMethod = 1.3.6.1.5.5.7.48.5 }, # caRepository
]
obj.tbsCertificate.extensions.sia1.extnValue = [
	# Access method with default value for certificate SIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.10 }, # rpkiManifest
	# Access method with no default value for certificate SIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.11 }, # signedObject
]
obj.tbsCertificate.extensions.sia2.extnValue = [
	# With type, without value
	{ accessLocation.type = iPAddress },
	# Without type, with value
	{ accessLocation.value = "type defaults to uniformResourceIdentifier" },
]
obj.tbsCertificate.extensions.aia2.extnValue = [
	# With type, without value
	{ accessLocation.type = rfc822Name },
	# Without type, with value
	{ accessLocation.value = whatever },
]

[node: B.mft]
obj.content.certificates.0.tbsCertificate.extensions = {
	sia1=sia, sia2=sia, aia=aia
}
obj.content.certificates.0.tbsCertificate.extensions.sia1.extnValue = [
	# Access method with no default value for signed object SIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.5 }, # caRepository
	# Access method with default value for signed object SIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.11 }, # signedObject
]
obj.content.certificates.0.tbsCertificate.extensions.sia2.extnValue = [
	# With type, without value
	{ accessLocation.type = dNSName },
	# Without type, with value
	{ accessLocation.value = IA5String },
]
obj.content.certificates.0.tbsCertificate.extensions.aia.extnValue = [
	# Access method with no default value for signed object AIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.2 }, # caIssuers
	# Access method with default value for signed object AIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.13 }, # rpkiNotify
]

[node: C.crl]
obj.tbsCertList.crlExtensions = { 1=sia, 2=sia, 3=aia }
obj.tbsCertList.crlExtensions.1.extnValue = [
	# Access methods with no default value for CRL SIAs
	{ accessMethod = 1.3.6.1.5.5.7.48.5 }, # caRepository
	{ accessMethod = 1.3.6.1.5.5.7.48.11 }, # signedObject
]
obj.tbsCertList.crlExtensions.2.extnValue = [
	# With type, without value
	{ accessLocation.type = registeredID },
	# Without type, with value
	{ accessLocation.value = striiiiiiing },
]
obj.tbsCertList.crlExtensions.3.extnValue = [{
	# With everything
	accessMethod = 1.3.6.1.5.5.7.48.5,
	accessLocation.type = registeredID,
	accessLocation.value = 1.4.8.16,
}]
