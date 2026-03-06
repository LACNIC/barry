ta.cer
	A.cer
		A.roa
	B.cer

[node: ta.cer]
rpp.notification = https://localhost:8443/rrdp/notification-2.xml

[notification: https://localhost:8443/rrdp/notification-2.xml]
snapshot = {
	uri = https://localhost:8443/rrdp/snapshot-2.xml,
	path = achoo.xml,
}
