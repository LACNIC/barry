ta.cer
	raw.cer
		raw.mft
		raw.roa
		raw.asa
	encoded.cer
		encoded.mft
		encoded.roa
		encoded.asa

[node: raw.mft]
# Raw 8str
obj.content.encapContentInfo.eContent = 0x010203

[node: encoded.mft]
# DER-encoded Manifest
obj.content.encapContentInfo.eContent = {
	manifestNumber = 0x05,
}

[node: raw.roa]
obj.content.encapContentInfo.eContent = 0x020304

[node: encoded.roa]
# DER-encoded RouteOriginAttestation
obj.content.encapContentInfo.eContent = {
	asId = 0xAABBCC,
}

[node: raw.asa]
obj.content.encapContentInfo.eContent = 0x050607

[node: encoded.asa]
# DER-encoded ASProviderAttestation
obj.content.encapContentInfo.eContent = {
	version = 4,
	customerASID = 0x0200,
	providers = [ 0x0100, 0x0300, 0x0400, 0x0555 ],
}
