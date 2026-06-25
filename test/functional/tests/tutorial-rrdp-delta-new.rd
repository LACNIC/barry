ta.cer 🛡️
	ca1.cer 🛡️
		roa1A.roa 🛡️
		roa1C.roa
		ca1.mft
		ca1.crl 🛡️
	ca2.cer 🛡️
		roa2.roa 🛡️
		ca2.mft 🛡️
		ca2.crl 🛡️
	ta.mft 🛡️
	ta.crl 🛡️

[node: ta.cer]
rpp.notification = https://your-server.net/rrdp/notif.xml

[notification: https://your-server.net/rrdp/notif.xml]
path = notif.xml
snapshot.uri = https://your-server.net/rrdp/snapshot.xml
snapshot.path = snapshot.xml