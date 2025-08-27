ta.cer
	ca1.cer
		roa1A.roa
		roa1B.roa
	ca2.cer
		roa2.roa

[node: ta.cer]
rpp.notification = https://your-server.net/rrdp/notif.xml

[notification: https://your-server.net/rrdp/notif.xml]
path = notif.xml
snapshot.uri = https://your-server.net/rrdp/snapshot.xml
snapshot.path = snapshot.xml