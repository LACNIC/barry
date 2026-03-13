ta.cer
	# Does not declare AS extension, gets default distribution
	auto.cer
		# Overrides AS extension
		overridden-explicit.cer
			# Does not declare AS extension, but parent does,
			# so child inherits parent's 1st ASN.
			inherits-explicit.asa
		# Overrides AS extension using 'inherit' alt
		overridden-inherit.cer
			# Does not declare AS extension, and parent inherits,
			# so child inherits grandparent's first AS.
			inherits-inherit.asa
#	lacks-ext.cer
#		achoo.asa

[node: overridden-explicit.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = [ 0x01000008-0x01000010 ]

[node: overridden-inherit.cer]
obj.tbsCertificate.extensions.as.extnValue.asnum = inherit

#[node: lacks-ext.cer]
#obj.tbsCertificate.extensions = [ bc, ski, aki, ku, cdp, aia, sia, cp, ip ]