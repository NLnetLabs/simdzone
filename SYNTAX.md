# Master files

Master files are text files that contain resource records (RRs) in text form.
Since the contents of a zone can be expressed in the form of a list of RRs, a
master file can be used to define a zone. Master files are commonly referred
to simply as zone files.

Master files were originally specified in [RFC1035 Section 5], but the DNS
has seen many additions since and the specification is rather ambiguous.
Consequently, various name servers implement slightly different dialects. This
document aims to clarify the format by listing (some of) the relevant
specifications and then proceed to explain how the text is interpreted by
simdzone.

* [RFC1035 Section 5](https://datatracker.ietf.org/doc/html/rfc1035#section-5)
* [RFC2308 Section 4](https://datatracker.ietf.org/doc/html/rfc2308#section-4)
* [RFC3597 Section 5](https://datatracker.ietf.org/doc/html/rfc3597#section-5)
* [draft-ietf-dnsop-svcb-https Section 2.1](https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-12.html#name-zone-file-presentation-form)


## Clarification (work-in-progress)

Historically, master files where editted by hand, which is reflected in the
syntax. Consider the format a tabular serialization format with some provisions
for easier editing. i.e. the owner, class and ttl fields may be omitted
(provided the line starts with \<blank\> for the owner) and $INCLUDE directives
can be used as templates.

The format is NOT context-free. The field following the owner (if specified)
may represent either a type, class or ttl and a symbolic constant, e.g. A
or NS, may have a different meaning if specified as an RDATA field.

The DNS is intentionally extensible. The specification is not explicit about
how that affects syntax, but it may explain why no specific notation for
data-types is enforced. To make it easier for data-types to be added at a later
stage the syntax cannot enforce a certain notation (or the scanner would need
to be revised). As such, it seems logical for the scanner to only identify
\<character-string\>`, which can be expressed as either a contiguos set of
characters without interior spaces, or as a quoted string.

The format allows for including structural characters in fields by means of
escaping the actual character or enclosing the field in quotes. The example
provided by the specification here is using ASCII dots in domain name labels.
The dot is normally a label separater, replaced by the length of the label
on the wire. If a domain name includes an actual ASCII dot, the character
must be escaped in the textual representation (`\X` or `\DDD`).

Note that ASCII dot characters must be escaped wheter the name is contained
in a quoted section or not. The same is not true for newlines and parentheses.

Going by the specification, integer values like the TTL may be written as
a plain number, contain escape sequences (\DDD can encode an ASCII digit) or
may be enclosed in quotes. However, going by common sense, writing it down as
anything but a plain number only requires more space and needlessly
complicates things (impacting parsing performance). The pragmatic approach is
to allow escape sequences only in fields that may actually contain data that
needs escaping (domain names and text strings).

* Some integer fields allow for using symbolic values. e.g. the algorithm
  field in RRSIG records.

* A freestanding @ denotes the current origin, but it really only makes sense
  for fields where a domain name is expected. The behavior is such that a
  domain name is inserted, NOT a simple text replacement.

* Class and type names are mutually exclusive because the class is optional,
  so the parser cannot distinguish between the two in text representation.

* The encoding is non-ASCII. Some characters have special meaning, but users
  are technically allowed to put in non-printable octets outside the ASCII
  range without custom encoding.
  Of course, this rarely occurs in practice and users are encouraged to use
  the \DDD encoding for "special".

* Parenthesis may not be nested.

* $ORIGIN must be an absolute domain.

* Escape sequences must not be unescaped in the lexer as is common with
  programming languages like C that have a preprocessor. Instead, the
  original text is necessary in the parsing stage to distinguish between dots.
