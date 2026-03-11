ta.cer
	ca.cer
		aspa.asa

[node: ta.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x10, 0x20, 0x30 ]

[node: ca.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x10, 0x20 ]

[node: aspa.asa]
obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum = [ 0x20 ]
obj.content.encapContentInfo.eContent = {
	customerASID = 0x20,
	providers = [ 0x0100 ],
}