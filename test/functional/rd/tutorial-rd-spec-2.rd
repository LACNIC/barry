ta.cer

[node: ta.cer]
# This line is a comment <-- 1
tbsCertificate = { # <-- 4
	validity = {
		notBefore = 2025-06-01T00:00:00Z, # <-- 4 (x2)
		notAfter = 2026-06-01T00:00:00Z
	},
	extensions.ip.extnValue = [ # <-- 5
		192.0.2.0/24-28,
		2001:db8::/64, # <-- 3
	], # <-- 3
}
