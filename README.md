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

./rsync/ta/ca1.cer	# The default name of each Repository Publication Point
./rsync/ta/ca2.cer	# is the name of its CA's certificate, minus extension.
./rsync/ta/ca3.cer
./rsync/ta/ta.crl	# CRLs & Manifests are spawned and also named automatically after the parent.
./rsync/ta/ta.mft	# You can declare them in the tree if you don't want this.

./rsync/ca1/roa1A.roa
./rsync/ca1/roa1B.roa
./rsync/ca1/ca1.crl
./rsync/ca1/ca1.mft

./rsync/ca2/roa2.roa
./rsync/ca2/ca2.crl
./rsync/ca2/ca2.mft

./rsync/ca3/roa3A.roa
./rsync/ca3/roa3B.roa
./rsync/ca3/ca3.crl
./rsync/ca3/ca3.mft
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

[node: roa.roa]
obj.content.encapContentInfo.eContent.version = 2
```

Basically, you can override fields from the objects by appending an "attributes" section to the RD. Enclose the name of the file in brackets (as a header), then override needed values one line at a time. You can do this for all the declared files in the tree. The keys of the fields are dot-stringified versions of their official names from the [RFC ASN.1 definitions](https://github.com/NICMx/libasn1fort/tree/main/asn1) (plus an "`obj.`" prefix), though there are additional keys we'll discuss later.

Processing that file should result in a repository that might be rejected by a current validator:

```bash
$ rm -rf rsync/
$ barry bad.repo
$ find rsync/ -type f	# Just to see them
rsync/ta.cer
rsync/ta/roa.roa
rsync/ta/ta.crl
rsync/ta/ta.mft
$ fort --mode=standalone --tal=bad.tal --validation-log.enabled --validation-log.level=info --log.level=info
...
Jul 14 13:26:41 ERR [Validation]: rsync://localhost:8873/rpki/ta/roa.roa: ROA's version (2) is nonzero.
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
$ barry -p csv minimal.repo > tree.csv
```

[This](sample/tree.csv) would be `tree.csv`.

Incidentally, this is an okay way to find all the available keys for a given file type.

## Repository Descriptor specification prototype

Reminder: This is a WIP. It's liable to change backwards-incompatibly until `barry` version 1.0.0 has been consumated.

The confirmed reserved characters are `=` (assignment), `,` (separator), `{` and `}` (map delimiters), `[` and `]` (array/set delimiters) and `#` (comment).

The only other token type is String, which is either

1. A continuous sequence of unreserved and non-whitespace characters (eg. `10`, `0x0100`, `potatoes`, `192.0.2.0/24-28`),
2. or a quoted sequence of any character except `"` (eg. `"also a string"`, `"!#$%^&*()[]{}"`). (There is no way to escape `"` at the moment.)

The key-value section is a JSON-adjacent hierarchy. Here is an example in which the user has overridden the valid dates of the TA and the addresses it can delegate:

```
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
[node: ta.cer]
# This line is a comment <-- 1
obj.tbsCertificate = { # <-- 4, 5
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
[node: ta.cer]
obj.tbsCertificate.validity.notBefore = 2025-06-01T00:00:00Z
obj.tbsCertificate.validity.notAfter = 2026-06-01T00:00:00Z
obj.tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24-28, 2001:db8::/64 ]
```

(See [Numerics](#numerics) below for an example of 6.)

## Attribute Data Types

### Numerics

Because of their numeric natures, `INTEGER`, `BOOLEAN`s, `OCTET STRING`s, `BIT STRING`s and `ANY`s largely share the same parser:

```
# INTEGER
obj.tbsCertificate.version = 4660
obj.tbsCertificate.version = 0x1234
obj.tbsCertificate.version = 0b0001001000110100

# BOOLEAN
obj.tbsCertificate.extensions.bc.critical = 9999

# OCTET STRING
obj.content.signerInfos.0.signature = 4660

# BIT STRING
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1234

# ANY
obj.tbsCertificate.signature.parameters = 0b0001001000110100
```

Hexadecimals and binaries are simultaneously integers and byte arrays. They can be very long, and you get one byte every two hexadecimal digits or eight binary ones:

```
# Array: { 0x12, 0x34, 0x56 }
obj.tbsCertificate.signature.parameters = 0x123456
# BTW: You can use colons or underscores as visual separators.
# If you quote the number, you can also use whitespace.
obj.tbsCertificate.signature.parameters = "0b_0001:0010_0011,0100 0101 0110"
# Note, quoted strings are allowed to span several lines.
obj.tbsCertificate.signature.parameters = "0x
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
obj.tbsCertificate.version = 0x00000001
# This ANY actually encodes into { 0, 0, 0, 1 }.
obj.tbsCertificate.signature.parameters = 0x00000001
```

If you want a `BIT STRING` whose bit count is not a multiple of 8, use hexadecimal or binary format, then a prefix length (which behaves pretty much like in IP addresses). The following three are equivalent:

```
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b:11:11:10
# The /6 chops off the last two bits
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0xF8/6
# The /6 actually adds a zero, because there are only 5 digits
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0b11111/6
```

(Please note that prefixing swaps the anchoring of the number! As an `INTEGER`, `0x1234` equals `0x001234`, but `0x1234/24` equals `0x123400`.)

Prefix lengths give you free padding, I guess. The following two are equivalent:

```
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1000000000000000000000000000000000
obj.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x10/136
```

Prefixing is actually also compatible with the other "numeric" data types, but they actually require the length to be a multiple of 8. You may abuse this to produce big numbers:

```
# Big integer whose hexadecimal representation consists of '1' followed by 248 zeroes.
obj.tbsCertificate.version = 0x01/1000
```

I haven't implemented negative `INTEGER`s yet.

### Booleans

`BOOLEAN`s are numeric data types, but they also allow case-sensitive `true` and `false`:

```
obj.tbsCertificate.extensions.ip.critical = 0xFF
obj.tbsCertificate.extensions.asn.critical = true
obj.tbsCertificate.extensions.ski.critical = false
```

Despite access to the numeric parser, booleans are internally managed as `int`s. This means you cannot assign big integers to them; your numeric boolean inputs need to be constrained to the range [`INT_MIN`, `INT_MAX`]. (The values of `INT_MIN` and `INT_MAX` depend on your system.)

That said, DER defines a very limited boolean range. `false` needs to be encoded as 0, and `true` needs to be encoded as 0xFF. `libasn1fort` currently does not provide a means to encode dirty BER, so for now, any nonzero value you enter will be snapped back to 0xFF.

### Object Identifiers (OIDs)

Only the numerical representation is supported.

```
obj.content.encapContentInfo.eContentType = 1.2.840.113549.1.9.16.1.26
```

### Dates

Only the `%Y-%m-%dT%H:%M:%SZ` format is supported right now.

```
obj.tbsCertificate.validity.notBefore = 2025-07-15T19:39:38Z
```

Applies to both `Time`s and `GeneralizedTime`s. Notice the UTC+0 enforcement.

### Names

Names consist of a [single choice](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L240-L241) (`rdnSequence`) consisting of [arrays](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L243) of [arrays of `AttributeNameAndValue`s](https://github.com/NICMx/libasn1fort/blob/main/asn1/rfc5280-a.1.asn1#L247). Formally, an overly-populated certificate name `subject` might look like this:

```
obj.tbsCertificate.subject.rdnSequence = [
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
obj.tbsCertificate.extensions = [ bc, ski, ku, sia, cp, ip, asn ]

# Regular CAs
obj.tbsCertificate.extensions = [ bc, ski, aki, ku, crldp, aia, sia, cp, ip, asn ]

# End-Entities
obj.content.certificates.0.tbsCertificate.extensions = [
	ski, aki, ku, crldp, aia, sia, cp, ip, asn
]

# CRLs
obj.tbsCertList.crlExtensions = [ aki, crln ]
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
obj.tbsCertificate.extensions.ip.extnID = 1.3.6.1.5.5.7.1.28
obj.tbsCertificate.extensions.ip.critical = true
obj.tbsCertificate.extensions.ip.extnValue = [ 192.0.2.0/24, 2001:db8::/96 ]
obj.tbsCertificate.extensions.asn.extnID = 1.3.6.1.5.5.7.1.29
obj.tbsCertificate.extensions.asn.critical = true
obj.tbsCertificate.extensions.asn.extnValue.asnum = [ 0x1234, 0x5678 ]
obj.tbsCertificate.extensions.asn.extnValue.rdi = [ 0x9ABC, 0xDEF0 ]
```

If you want a different extension list, override it:

```
# Replaces the extension list with an IP extension (type "ip", name "ip")
# and an ASN extension (type "asn", name "asn").
obj.tbsCertificate.extensions = [ ip, asn ]

# The "ip" label now refers to the first extension (because that's the one named "ip" now),
# not the (now nonexistent) 6th or 9th.
obj.tbsCertificate.extensions.ip.extnID = 1.2.3.4.5
```

You can customize the extension names by declaring the `extensions` object as a map. This is useful if you want to list multiple extensions of the same type:

```
obj.tbsCertificate.extensions = {
	# <name> = <type>
	red = ip,
	blue = asn,
	yellow = ip,
	purple = bc,
	orange = ip,
	green = asn
}

# Overrides the OID of the third ip extension
obj.tbsCertificate.extensions.orange.extnID = 1.2.3.4.5
```

Whether declared as a set or map, the final list will contain the extensions in the same order in which they were declared.

### IP Resources

```
obj.content.encapContentInfo.eContent.ipAddrBlocks = [
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
[node: mft.mft]
obj.content.encapContentInfo.eContent.fileList = {
	# <File name> = <Hash>
	crl.crl = 0x14A9B4039E1EDC10C1314C435828B418417E8B152CD173696B776EF24D9A9E41,
	A.cer   = 0x5EBFE949DAB77A1AED18BC7EDE86C0F4CC784A2227385E6F04461EE85BD7F2C9,
	B.cer   = 0x237FF39E12A09160CC2B365BB155D72A25E1CF9073CD583AADAA35E2872AD104
}
```

(If you omitted the CRL in the tree, it will be automatically added to the `fileList` as the last entry.)

Since the files are `fileList`ed in the order in which they were declared in the tree, you can then (for example) override the hash of `A.cer` and the name of `B.cer` like so:

```
# Indexing is zero-based
obj.content.encapContentInfo.eContent.fileList.1.hash = 0x010203
obj.content.encapContentInfo.eContent.fileList.2.file = potatoes
```

Or just override the entire list however you see fit:

```
obj.content.encapContentInfo.eContent.fileList = {
	A.cer           = 0x010203,
	nonexistent.cer = 0x040506,
	mft.mft         = 0x112233,
	foobar          = 0x55555555555555
}
```

## Tutorial: RRDP

RRDP has two relevant program arguments:

```
barry
    --rrdp-uri=<RRDP-URI>    # default: https://localhost:8080/rpki
    --rrdp-path=<RRDP-PATH>  # default: rrdp/
    ...
```

By default, all the non-TA tree files `barry` produces are snapshot'd into `<RRDP-PATH>/snapshot.xml` (which is assumed to be served from URL `[RRDP-URI]/snapshot.xml`), which is then referenced by `<RRDP-PATH>/notification.xml` (`[RRDP-URI]/notification.xml`). <s>Simply because of inertia, the TA is copied to `<RRDP-PATH>/<Name of TA>` (`[RRDP-URI]/<Name of TA>`).</s> No deltas are produced.

> Note: If `--rrdp-uri` is an empty string, RRDP will be completely disabled. (SIAs will not contain `rpkiNotify`s and RRDP files will not be generated.) Otherwise, if `rrdp-path` is an empty string, the SIAs will contain the corresponding `rpkiNotify`s, but no RRDP XMLs will be generated.

Every certificate in the tree has an additional key-value URL named `rpp.notification`, which is normally autocomputed early in the repository building process. If you don't override anything else, all of said certificate's descendants will be snapshot'd into the `rpp.notification` RRDP context:

```
ta.cer
	A.cer
		A1.roa
		A2.roa
	B.cer
		B1.roa
		B2.cer
			B2a.roa

[node: ta.cer]
rpp.notification = https://potato/rrdp/notification.xml

[node: B.cer]
rpp.notification = https://tomato/rrdp/notification.xml

[node: B2.cer]
rpp.notification = https://lettuce/rrdp/notification.xml
```

- `potato`'s snapshot will contain `A.cer`, `A1.roa`, `A2.roa` and `B.cer`.
- `tomato`'s snapshot will contain `B1.roa` and `B2.cer`.
- `lettuce`'s snapshot will contain `B2a.roa`.

> Note: If the object is the TA, its default `rpp.notification` is `[RRDP-URI]/snapshot.xml`. Otherwise, its default is inherited from its parent.

> Note: `rpp.notification` is also copied to the certificate's `rpkiNotify` (in its SIA extension), though [that can also be overridden](test/functional/rd/gname.rd).

You can also induce further chaos by overriding the files actually contained by each snapshot, whether it makes sense or not:

```
[notification: https://tomato/rrdp/notification.xml]
snapshot.files = [ ta.cer, A1.roa, A1.roa, B2a.roa ]
```

I haven't implemented deltas yet.

## TODO

Add Github issues:

- Configuration file section: `[Alias]`
- `include`s is configuration
- RRDP deltas
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
