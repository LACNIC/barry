ta.cer
	# Does not declare IP extension, gets default distribution
	auto.cer
		# Overrides IP extension
		overridden-explicit.cer
			# Does not declare IP extension, but parent does,
			# so child inherits all parent IPs.
			inherits-explicit.roa
		# Overrides IP extension using 'inherit' alt
		overridden-inherit.cer
			# Does not declare IP extension, but parent does,
			# so child inherits 'inherit' alt.
			inherits-inherit.roa
#	lacks-ext.cer
#		achoo.roa

[node: overridden-explicit.cer]
obj.tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24, 2001:db8::/96 ]

[node: overridden-inherit.cer]
obj.tbsCertificate.extensions.ip.extnValue = inherit

#[node: lacks-ext.cer]
#obj.tbsCertificate.extensions = [ bc, ski, aki, ku, cdp, aia, sia, cp, as ]