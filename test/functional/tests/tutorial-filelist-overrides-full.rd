ta.cer
	mft.mft
	crl.crl
	A.cer
	B.cer

[node: mft.mft]
obj.content.encapContentInfo.eContent.fileList = {
	A.cer           = 0x010203,
	nonexistent.cer = 0x040506,
	mft.mft         = 0x112233,
	foobar          = 0x55555555555555
}
