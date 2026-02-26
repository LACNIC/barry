ta.cer
	A.cer
		AA.crl
		AB.mft
	B.crl
	C.mft
	D.roa

[node: ta.cer]
uri = https://abc
path = custom/rpp-test/ta
rpp.uri = rsync://caRepo/rpp-ta
rpp.path = custom/rpp-test/rpp-ta
rpp.notification = https://rpkiNotif
