ta.cer
	A.cer
	B.cer
	C.cer

[node: A.cer]
obj.tbsCertificate.extensions.sia.extnValue = [
	{
		accessMethod = 1.3.6.1.5.5.7.48.10,
		accessLocation.type = rfc822Name,
		accessLocation.value = "yeah sure",
	}, {
		accessMethod = 1.3.6.1.5.5.7.48.5,
		accessLocation.type = iPAddress,
		accessLocation.value = 0x010203,
	}, {
		accessMethod = 1.3.6.1.5.5.7.48.13,
		accessLocation.type = registeredID,
		accessLocation.value = 1.3.6.1.5.5.7.48.13,
	}
]

[node: B.cer]
obj.tbsCertificate.extensions.sia.extnValue = [{
	accessMethod = 1.3.6.1.5.5.7.48.10,
	accessLocation.type = rfc822Name,
	accessLocation.value = "yeah sure",
}]
obj.tbsCertificate.extensions.sia.extnValue.0.accessMethod = 1.3.6.1.5.5.7.48.13
obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type = dNSName

[node: C.cer]
obj.tbsCertificate.extensions.sia.extnValue = [{
	accessMethod = 1.3.6.1.5.5.7.48.10,
	accessLocation.type = rfc822Name,
	accessLocation.value = "yeah sure",
}]
obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.type = dNSName
obj.tbsCertificate.extensions.sia.extnValue.0.accessLocation.value = "separate"
