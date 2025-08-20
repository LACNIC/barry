ta.cer
	ca1.cer

[node: ca1.cer]
tbsCertificate.subject.rdnSequence = [
	[ # RelativeDistinguishedName 1
		{ # AttributeTypeAndValue 1
			type = 2.5.4.3,   # commonName
			value = aaa
		},
		{ # AttributeTypeAndValue 2
			type = 2.5.4.5,   # serialNumber
			value = bbb
		},
	],
	[ # RelativeDistinguishedName 2
		{ # AttributeTypeAndValue 1
			type = 2.5.4.4,   # surname
			value = ccc
		},
		{ # AttributeTypeAndValue 2
			type = 2.5.4.42,  # givenName
			value = ddd
		},
		{ # AttributeTypeAndValue 3
			type = 2.5.4.43,  # initials
			value = eee
		}
	]
]
