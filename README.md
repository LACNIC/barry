# BARRY

A program that can generate a BAd Rpki RepositorY.

Meant for Relying Party testing.

WIP.

## Installation

```bash
mkdir -p ~/git

cd ~/git
git clone https://github.com/vlm/asn1c.git
cd asn1c
test -f configure || autoreconf -iv
./configure
make
sudo make install

cd ~/git
git clone https://github.com/NICMx/libasn1fort
cd libasn1fort
./autogen.sh
./configure
make
sudo make install
sudo ldconfig

cd ~/git
git clone https://github.com/LACNIC/barry
cd barry
./autogen.sh
./configure
make
sudo make install
```

## Tutorial: Simple correct repository

Let's say we want to create the following tree:

```
                        ╔══════╗
                        ║  TA  ║
                        ╚══╤═══╝
                           │
         ┌─────────────────┼────────────────┐
         │                 │                │
      ╔══╧═══╗          ╔══╧═══╗         ╔══╧═══╗
      ║ CA 1 ║          ║ CA 2 ║         ║ CA 3 ║
      ╚══╤═══╝          ╚══╤═══╝         ╚══╤═══╝
         │                 │                │
    ┌────┴─────┐           │           ┌────┴─────┐
    │          │           │           │          │
╔═══╧════╗ ╔═══╧════╗  ╔═══╧════╗  ╔═══╧════╗ ╔═══╧════╗
║ ROA 1A ║ ║ ROA 1B ║  ║ ROA 2  ║  ║ ROA 3A ║ ║ ROA 3B ║
╚════════╝ ╚════════╝  ╚════════╝  ╚════════╝ ╚════════╝
```

Produce a Repository Descriptor (RD) file named `good.repo`, containing the tree drawing in minimal text form:

```
ta.cer
	ca1.cer
		roa1A.roa
		roa1B.roa
	ca2.cer
		roa2.roa
	ca3.cer
		roa3A.roa
		roa3B.roa
```

Whitespace decides familial ties. (A node with a given indentation will be the child of the most recent file with smaller indentation, files with equal indentation and common parent are siblings.) Tabs are valued as 8 spaces, though nothing actually needs to be constrained to multiples of 8.

Feed the RD to `barry`:

```bash
$ barry good.repo
```

It'll make a bunch of assumptions and output the following file hierarchy:

```bash
./good.tal		# Named based on the RD

./rsync/ta.cer

./rsync/rpp0/ca1.cer	# "RPP" stands for "Repository Publication Point."
./rsync/rpp0/ca2.cer	# They're numbered monotonically.
./rsync/rpp0/ca3.cer	# Hence, "rpp0" is always the TA's RPP.
./rsync/rpp0/0.crl
./rsync/rpp0/0.mft

./rsync/rpp1/roa1A.roa
./rsync/rpp1/roa1B.roa
./rsync/rpp1/1.crl	# CRLs & Manifests are spawned and named automatically.
./rsync/rpp1/1.mft	# You can declare them in the tree if you don't want this.

./rsync/rpp2/roa2.roa
./rsync/rpp2/2.crl
./rsync/rpp2/2.mft

./rsync/rpp3/roa3A.roa
./rsync/rpp3/roa3B.roa
./rsync/rpp3/3.crl
./rsync/rpp3/3.mft
```

Serve them via rsync, and you've built yourself a "validateable" Repository Instance (assuming your RP can be configured to allow requests to localhost):

```bash
$ cat > rsyncd.conf <<\EOF
lock file = lock.lock
log file = log.log
pid file = pid.pid
port = 8873

[rpki]
	path = rsync/
	hosts = 127.0.0.1
EOF
$ rsync --daemon --config=rsyncd.conf
$ fort --mode=standalone --tal=good.tal --log.level=info | tail -5
Jul 14 13:06:30 INF: Validation finished:
Jul 14 13:06:30 INF: - Valid ROAs: 1
Jul 14 13:06:30 INF: - Valid Router Keys: 0
Jul 14 13:06:30 INF: - Real execution time: 1s
Jul 14 13:06:30 INF: Done.
```

As you might imagine, this means keys, signatures, serials, names and dates are all automatically generated (the latter default to the current time).

## Tutorial: Simple incorrect repository

Let's say we want to validate the following RFC 6482 requirement:

> 3.1.  version
> 
>    The version number of the RouteOriginAttestation MUST be 0.

This tree'll suffice:

```
    ╔═════╗
    ║ TA  ║
    ╚══╤══╝
╔══════╧═══════╗
║     ROA      ║
║ (version: 2) ║
╚══════════════╝
```

That translates into `bad.repo`:

```
ta.cer
	roa.roa

[roa.roa]
content.encapContentInfo.eContent.version = 2
```

Basically, you can override fields from the objects by appending an "attributes" section to the RD. Enclose the name of the file in brackets (as a header), then override needed values one line at a time. You can do this for all the declared files in the tree. The keys of the fields are dot-stringified versions of their official names from the [RFC ASN.1 definitions](https://github.com/NICMx/libasn1fort/tree/main/asn1), though there are additional keys we'll discuss later.

Processing that file should result in a repository that might be rejected by a current validator:

```bash
$ rm -rf rsync/
$ barry bad.repo
$ find rsync/ -type f	# Just to see them
rsync/ta.cer
rsync/rpp0/roa.roa
rsync/rpp0/0.crl
rsync/rpp0/0.mft
$ fort --mode=standalone --tal=bad.tal --validation-log.enabled --validation-log.level=info --log.level=info
...
Jul 14 13:26:41 ERR [Validation]: rsync://localhost:8873/rpki/rpp0/roa.roa: ROA's version (2) is nonzero.
...
Jul 14 13:26:41 INF: Validation finished:
Jul 14 13:26:41 INF: - Valid ROAs: 0
...
```

With this, you can create some manner of testing mechanism by checking the presence of outputted ROAs, stat querying and/or maybe log grepping.

## Tutorial: Verbose output

By default, `barry` tries to keep quiet. Add `-p (markdown|csv)` to print the objects and all of their values, `-v` if you want a general idea of what it's doing, and another `-v` for garbage tracing.

```bash
$ echo "ta.cer" > minimal.repo
$ barry -p markdown minimal.repo > tree.md
```

[This](sample/tree.md) would be `tree.md`.

Incidentally, this is an okay way to find all the available keys for a given file type.

## Repository Descriptor specification prototype

Reminder: This is a WIP. It's liable to change backwards-incompatibly until `barry` version 1.0.0 has been consumated.

The confirmed reserved characters are `=` (assignment), `,` (separator), `{` and `}` (map delimiters), `[` and `]` (array/set delimiters) and `#` (comment).

The only other token type is String, which is either

1. A continuous sequence of unreserved and non-whitespace characters (eg. `10`, `0x0100`, `potatoes`, `192.0.2.0/24-28`),
2. or a quoted sequence of any character except `"` (eg. `"also a string"`, `"!#$%^&*()[]{}"`). (There is no way to escape `"` at the moment.)

The key-value section is a JSON-adjacent hierarchy. Here is an example in which the user has overridden the valid dates of the TA and the addresses it can delegate:

```
[ta.cer]
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
```

It differs from JSON in several ways:

1. You can comment out the remainder of a line by issuing the `#` character outside of a string,
2. as you can see above, the assignment reserved character is `=` (not `:`),
3. the last element of any set or map is allowed to be suffixed by a redundant comma (for reduced diff noise),
4. if a string (whether key or value) does not contain reserved characters or whitespace, then you can omit the quotes,
5. you can reduce stacking by dot-chaining field names as you see fit,
6. and quoted strings can contain newlines.

Hence, the example above is equivalent to

```
[ta.cer]
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
```

Which is also equivalent to

```
[ta.cer]
tbsCertificate.validity.notBefore = 2025-06-01T00:00:00Z
tbsCertificate.validity.notAfter = 2026-06-01T00:00:00Z
tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24-28, 2001:db8::/64 ]
```

(See [Numerics](#numerics) below for an example of 6.)

## Attribute Data Types

### Numerics

Because of their numeric natures, `INTEGER`, `BOOLEAN`s, `OCTET STRING`s, `BIT STRING`s and `ANY`s largely share the same parser:

```
# INTEGER
tbsCertificate.version = 4660
tbsCertificate.version = 0x1234
tbsCertificate.version = 0b0001001000110100

# BOOLEAN
tbsCertificate.extensions.bc.critical = 9999

# OCTET STRING
content.signerInfos.0.signature = 4660

# BIT STRING
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1234

# ANY
tbsCertificate.signature.parameters = 0b0001001000110100
```

Hexadecimals and binaries are simultaneously integers and byte arrays. They can be very long, and you get one byte every two hexadecimal digits or eight binary ones:

```
# Array: { 0x12, 0x34, 0x56 }
tbsCertificate.signature.parameters = 0x123456
# BTW: You can use colons or underscores as visual separators.
# If you quote the number, you can also use whitespace.
tbsCertificate.signature.parameters = "0b_0001:0010_0011,0100 0101 0110"
# Note, quoted strings are allowed to span several lines.
tbsCertificate.signature.parameters = "0x
	00a1 00a2 00a3 00a4 00a5 00a6 00a7 00a8
	80b1 80b2 80b3 80b4 80b5 80b6 80b7 80b8
	A0c1 A0c2 A0c3 A0c4 A0c5 00c6 A0c7 A0c8
	F0d1 F0d2 F0d3 F0d4 F0d5 F0d6 F0d7 F0
"
```

Also notice, this is the human-readable value. It later gets DER-encoded, which might result in some mutations, such as truncated leading zeroes on `INTEGER`s:

```
# This INTEGER Becomes { 2, 1, 1 } when encoded.
# (2 = INTEGER type, 1 = length, 1 = value, leading zeroes excluded)
tbsCertificate.version = 0x00000001
# This ANY actually encodes into { 0, 0, 0, 1 }.
tbsCertificate.signature.parameters = 0x00000001
```

If you want a `BIT STRING` whose bit count is not a multiple of 8, use hexadecimal or binary format, then a prefix length (which behaves pretty much like in IP addresses). The following three are equivalent:

```
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b:11:11:10
# The /6 chops off the last two bits
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0xF8/6
# The /6 actually adds a zero, because there are only 5 digits
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b11111/6
```

(Please note that prefixing swaps the anchoring of the number! As an `INTEGER`, `0x1234` equals `0x001234`, but `0x1234/24` equals `0x123400`.)

Prefix lengths give you free padding, I guess. The following two are equivalent:

```
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1000000000000000000000000000000000
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x10/136
```

Prefixing is actually also compatible with the other "numeric" data types, but they actually require the length to be a multiple of 8. You may abuse this to produce big numbers:

```
# Big integer whose hexadecimal representation consists of '1' followed by 248 zeroes.
content.encapContentInfo.eContent.version = 0x01/1000
```

I haven't implemented negative `INTEGER`s yet.

### Booleans

`BOOLEAN`s are numeric data types, but they also allow case-sensitive `true` and `false`:

```
tbsCertificate.extensions.ip.critical = 0xFF
tbsCertificate.extensions.asn.critical = true
tbsCertificate.extensions.ski.critical = false
```

Despite access to the numeric parser, booleans are internally managed as `int`s. This means you cannot assign big integers to them; your numeric boolean inputs need to be constrained to the range [`INT_MIN`, `INT_MAX`]. (The values of `INT_MIN` and `INT_MAX` depend on your system.)

That said, DER defines a very limited boolean range. `false` needs to be encoded as 0, and `true` needs to be encoded as 0xFF. `libasn1fort` currently does not provide a means to encode dirty BER, so for now, any nonzero value you enter will be snapped back to 0xFF.

### Object Identifiers (OIDs)

Only the numerical representation is supported.

```
content.encapContentInfo.eContentType = 1.2.840.113549.1.9.16.1.26
```

### Dates

Only the `%Y-%m-%dT%H:%M:%SZ` format is supported right now.

```
tbsCertificate.validity.notBefore = 2025-07-15T19:39:38Z
```

Applies to both `Time`s and `GeneralizedTime`s. Notice the UTC+0 enforcement.

### Names

Names consist of a [single choice](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L240-L241) (`rdnSequence`) consisting of [arrays](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L243) of [arrays of `AttributeNameAndValue`s](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L247). Formally, an overly-populated certificate name `subject` might look like this:

```
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
```

RPKI mostly only requires a single `RelativeDistinguishedName` containing `commonName` and (optionally) `serialNumber`.

### Extensions

By default, your certificates get the following extension lists:

```
# TAs
tbsCertificate.extensions = [ bc, ski, ku, sia, cp, ip, asn ]

# Regular CAs
tbsCertificate.extensions = [ bc, ski, aki, ku, crldp, aia, sia, cp, ip, asn ]

# End-Entities
content.certificates.0.tbsCertificate.extensions = [
	ski, aki, ku, crldp, aia, sia, cp, ip, asn
]

# CRLs
tbsCertList.crlExtensions = [ aki, crln ]
```

The presently implemented extensions are

| Initials | Extension                    | Reference |
|----------|------------------------------|-----------|
| bc       | Basic Constraints            | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.1) |
| ski      | Subject Key Identifier       | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.2) |
| aki      | Authority Key Identifier     | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.3) |
| ku       | Key Usage                    | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.4) |
| crldp    | CRL Distribution Points      | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.6) |
| aia      | Authority Information Access | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.7) |
| sia      | Subject Information Access   | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.8) |
| cp       | Certificate Policies         | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.9) |
| ip       | IP Resources                 | [Generic](https://datatracker.ietf.org/doc/html/rfc3779#section-2), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.10) |
| asn      | AS Resources                 | [Generic](https://datatracker.ietf.org/doc/html/rfc3779#section-3), [RPKI](https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.11) |
| crln     | CRL Number                   | [Generic](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3) |

Every extension gets an `extnID` OID, a `critical` boolean and a type-dependent `extnValue`, all editable through subfields:

```
tbsCertificate.extensions.ip.extnID = 1.3.6.1.5.5.7.1.28
tbsCertificate.extensions.ip.critical = true
tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24, 2001:db8::/96 ]
tbsCertificate.extensions.asn.extnID = 1.3.6.1.5.5.7.1.29
tbsCertificate.extensions.asn.critical = true
tbsCertificate.extensions.asn.extnValue.asnum = [ 0x1234, 0x5678 ]
tbsCertificate.extensions.asn.extnValue.rdi = [ 0x9ABC, 0xDEF0 ]
```

If you want a different extension list, override it. Assignments are handled sequentially:

```
# Override the OID of the default 6th extension
tbsCertificate.extensions.ip.extnID = 1.2.3.4.5

# Drop the default extensions, create a new list
# (The 1.2.3.4.5 OID dies as well)
tbsCertificate.extensions = [ ip, asn ]

# Override the OID of the first extension
tbsCertificate.extensions.ip.extnID = 1.2.3.4.5
```

You can also refer to extensions by (zero-based) index, which might be useful if you declare multiple of the same type:

```
tbsCertificate.extensions = [ ip, asn, ip, bc, ip, asn ]
# Overrides the OID of the third ip extension
tbsCertificate.extensions.4.extnID = 1.2.3.4.5
```

### IP Resources

```
content.encapContentInfo.eContent.ipAddrBlocks = [
	192.0.2.0/24,
	203.0.113.0,
	2001:db8::/40-48
]
```

List as many as you need. `barry` will automatically detect IP version and drop each entry to the corresponding `ROAIPAddressFamily`.

### fileList

> TODO this section is probably outdated

By default, `barry` populates manifest fileLists with the actual names and hashes of the files it creates. The following RD:

```
ta.cer
	mft.mft
	crl.crl
	A.cer
	B.cer
```

Implies (with possible hashes)

```
[mft.mft]
content.encapContentInfo.eContent.fileList = {
	# <File name>: <Hash>
	crl.crl: 0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41,
	A.cer:   0x5EBFE949DAB77A1AED18BC7EDE86C0F4CC784A2227385E6F04461EE85BD7F2C9,
	B.cer:   0x237FF39E12A09160CC2B365BB155D72A25E1CF9073CD583AADAA35E2872AD104
}
```

(If you omitted the CRL in the tree, it will be automatically added to the `fileList` as the last entry.)

Since the files are `fileList`ed in the order in which they were declared in the tree, you can then (for example) override the hash of `A.cer` and the name of `B.cer` like so:

```
# Indexing is zero-based
content.encapContentInfo.eContent.fileList.1.hash = 0x010203
content.encapContentInfo.eContent.fileList.2.file = potatoes
```

Or just override the entire list however you see fit:

```
content.encapContentInfo.eContent.fileList = {
	A.cer:           0x010203,
	nonexistent.cer: 0x040506,
	mft.mft:         0x112233,
	foobar:          0x55555555555555
}
```

## TODO

Add Github issues:

- Configuration file section: `[Alias]`
- `include`s is configuration
- I commented the RRDP code to force myself to upload the prototype today
- May want to purge all the memory leaks
- Still unimplemented fields
	- Certificates
		- issuerUniqueID
		- subjectUniqueID
	- CRLs
		- revokedCertificates
	- Certificate/CRL extensions
		- AKI authorityCertIssuer
		- CRLDP extnValue
		- AIA extnValue
		- SIA extnValue
		- CP extnValue
	- Manifests, ROAs
		- signedAttrs
		- unsignedAttrs
		- digestAlgorithms
		- crls
- Fields whose values are autocomputed even if overridden in RD
	- Several EE certificate extensions
- Document
	- Program arguments
