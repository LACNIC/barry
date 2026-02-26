ta.cer

[node: ta.cer]
"obj" = {
	"tbsCertificate" = {
		"validity" = {
			"notBefore" = "2025-06-01T00:00:00Z",
			"notAfter" = "2026-06-01T00:00:00Z"
		},
		"extensions" = {
			"ip" = { 
				"extnValue" = [
					"192.0.2.0/24-28",
					"2001:db8::/64"
				]
			}
		}
	}
}
