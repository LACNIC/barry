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
# Raw ANY
obj.content = 0x010203

[node: encoded.mft]
# DER-encoded SignedData
obj.content = { version = 0x05 }

[node: raw.roa]
obj.content = 0x020304

[node: encoded.roa]
obj.content = {
	encapContentInfo = {
		eContentType = 1.3.6.1.5.5.7.48.5
	}
}

[node: raw.asa]
obj.content = 0x050607

[node: encoded.asa]
obj = {
	content = {
		encapContentInfo = {
			eContent = {
				customerASID = 0x0100
			}
		}
	}
}
