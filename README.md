# BARRY

A program that can generate a BAd Rpki RepositorY.

Meant for Relying Party testing.

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

Basically, you can override fields from the objects by appending an "attributes" section to the RD. Enclose the name of the file in brackets (as a header), then override needed values one line at a time. You can do this for all the declared files in the tree. The keys of the fields are dot-stringified versions of their official names from the [RFC ASN.1 definitions](TODO), though there are additional keys we'll discuss later.

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

By default, `barry` tries to keep quiet. Add `-p` to print the objects and all of their values, `-v` if you want a general idea of what it's doing, and another `-v` for garbage tracing.

```bash
$ echo "ta.cer" > minimal.repo
$ barry -p minimal.repo > tree.md
```

[This](sample/tree.md) would be `tree.md`.

Incidentally, this is an okay way to find all the available keys for a given file type.

## Attribute Data Types

### Numerics

Because of their numeric natures, `INTEGER`, `OCTET STRING`s, `BIT STRING`s and `ANY`s largely share the same parser:

```
# INTEGER
content.encapContentInfo.eContent.version = 4660
content.encapContentInfo.eContent.version = 0x1234
content.encapContentInfo.eContent.version = 0b0001001000110100

# OCTET STRING
content.signerInfos[0].sid.subjectKeyIdentifier = 4660

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
```

Notice, this is the human-readable value. It later gets DER-encoded, which might result in some mutations, such as truncated leading zeroes on `INTEGER`s:

```
# This INTEGER Becomes { 2, 1, 1 } when encoded.
# (2 = INTEGER type, 1 = length, 1 = value, leading zeroes excluded)
content.encapContentInfo.eContent.version = 0x00000001  
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

> Please note that prefixing swaps the anchoring of the number! As an `INTEGER`, `0x1234` equals `0x001234`, but `0x1234/24` equals `0x123400`.

Prefix lengths give you free padding, I guess. The following two are equivalent:

```
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x1000000000000000000000000000000000
tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = 0x10/136
```

Prefixing is actually also compatible with the other "numeric" data types, but they actually require the length to be a multiple of 8. You may abuse this to produce big numbers:

```
# Big integer whose hexadecimal representation consists of '1' followed
# by 124 zeroes.
content.encapContentInfo.eContent.version = 0x01/1000
```

I haven't implemented negative `INTEGER`s yet.

### Object Identifiers

Only the numerical representation is supported right now.

```
content.encapContentInfo.eContentType = 1.2.840.113549.1.9.16.1.26
```

### Dates

Only the `%Y-%m-%dT%H:%M:%SZ` format is supported right now.

```
tbsCertificate.validity.notBefore = 2025-07-15T19:39:38Z
```

Applies to both `Time`s and `GeneralizedTime`s. Notice the UTC+0 enforcement.

### IP Resources

```
content.encapContentInfo.eContent.ipAddrBlocks = [ 192.0.2.0/24, 203.0.113.0, 2001:db8::/40-48 ]
```

List as many as you need. `barry` will automatically detect IP version and drop each entry to the corresponding `ROAIPAddressFamily`.

## TODO

Add Github issues:

- Configuration file section: `[Alias]`
- `include`s is configuration
- Allow newline escaping?
- I commented the RRDP code to force myself to upload the prototype today
- The key pair generation is taking too long; maybe provide a means to weaken the RNG
- May want to purge all the memory leaks