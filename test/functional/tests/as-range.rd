ta.cer
	ca.cer
		aspa.asa

[node: ta.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = [
	"0x10 - 0x20",
	0x30-0x40,
	0x1000-0x1234,
]

[node: ca.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x02-0x08 ]

[node: aspa.asa]
obj.content.certificates.0.tbsCertificate.extensions.as.extnValue.asnum = [ 0x04-0x06 ]
obj.content.encapContentInfo.eContent = {
	customerASID = 0x05,
	providers = [ 0x0100 ],
}