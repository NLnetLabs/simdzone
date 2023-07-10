# Zone files

Zone files are text files that contain resource records (RRs) in text form.
Zones can be defined by expressing them in the form of a list of RRs.

Zone files were originally specified in RFC1035 Section 5, but the DNS
has seen many additions since and the specification is rather ambiguous.
Consequently, various name servers implement slightly different dialects. This
document aims to clarify the format by listing (some of) the relevant
specifications and then proceed to explain why certain design decisions were
made in simdzone.

* [RFC1035 Section 5](https://datatracker.ietf.org/doc/html/rfc1035#section-5)
* [RFC2308 Section 4](https://datatracker.ietf.org/doc/html/rfc2308#section-4)
* [RFC3597 Section 5](https://datatracker.ietf.org/doc/html/rfc3597#section-5)
* [draft-ietf-dnsop-svcb-https Section 2.1](https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-12.html#name-zone-file-presentation-form)


## Clarification (work-in-progress)

> NOTE: BIND behavior is more-or-less considered the de facto standard.

Historically, master files where edited by hand, which is reflected in the
syntax. Consider the format a tabular serialization format with provisions
for easier editing. i.e. the owner, class and ttl fields may be omitted
(provided the line starts with \<blank\> for the owner) and $INCLUDE directives
can be used for templating.

The format is NOT context-free. The field following the owner (if specified)
may represent either a type, class or ttl and a symbolic constant, e.g. A
or NS, may have a different meaning if specified as an RDATA field.

The DNS is intentionally extensible. The specification is not explicit about
how that affects syntax, but it may explain why no specific notation for
data-types is enforced. To make it easier for data-types to be added at a later
stage the syntax cannot enforce a certain notation (or the scanner would need
to be revised). As such, it seems logical for the scanner to only identify
character strings, which can be expressed as either a contiguous set of
characters without interior spaces, or as a quoted string.

The format allows for including structural characters in fields by means of
escaping the actual character or enclosing the field in quotes. The example
provided by the specification here is using ASCII dots in domain name labels.
The dot is normally a label separator, replaced by the length of the label
on the wire. If a domain name includes an actual ASCII dot, the character
must be escaped in the textual representation (`\X` or `\DDD`).

Note that ASCII dot characters must be escaped whether the name is contained
in a quoted section or not. The same is not true for newlines and parentheses.

Going by the specification, integer values like the TTL may be written as
a plain number, contain escape sequences (\DDD can encode an ASCII digit) or
may be enclosed in quotes. However, going by common sense, writing it down as
anything but a plain number only requires more space and needlessly
complicates things (impacting parsing performance). The pragmatic approach is
to allow escape sequences only in fields that may actually contain data that
needs escaping (domain names and text strings).

RFC1035 states both \<contiguous\> and \<quoted\> are \<character-string\>.
However, it makes little sense to quote e.g. a TTL because it cannot contain
characters that overlap with any structural characters and in practice, it
really never happens. The same applies to base64 sequences, which was
specifically designed to encode binary data in printable ASCII characters. To
quote a field and include whitespace is more-or-less instructing the parser
to not ignore it. Fields that cannot contain structural characters, i.e.
anything other than domain names and text strings, MUST not be quoted.

> BIND does not accept quoted fields for A or NS RDATA. TTL values in SOA
> RDATA, base64 Signature in DNSKEY RDATA, as well as type, class and TTL
> header fields all result in a syntax error too if quoted.


* Some integer fields allow for using symbolic values. e.g. the algorithm
  field in RRSIG records.

* RFC1035 states: A freestanding @ denotes the current origin.
  There has been discussion in which locations @ is interpreted as the origin.
  e.g. how is a freestanding @ be interpreted in the RDATA section of a TXT RR.
  Note that there is no mention of text expansion in the original text. A
  freestanding @ denotes the origin. As such, it stands to reason that it's
  use is limited to locations where domain names are expected, which also
  happens to be the most practical way to implement the functionality.

  > This also seems to be the behavior that other name servers implement (at
  > least BIND and PowerDNS). The BIND manual states: "When used in the label
  > (or name) field, the asperand or at-sign (@) symbol represents the current
  > origin. At the start of the zone file, it is the \<zone\_name\>, followed
  > by a trailing dot (.).

  > It may also make sense to interpret a quoted freestanding @ differently
  > than a non-quoted one. At least, BIND throws an error if a quoted
  > freestanding @ is encountered in the RDATA sections for CNAME and NS RRs.
  > However, a quoted freestanding @ is accepted and interpreted as origin
  > if specified as the OWNER.

  > Found mentions of what happens when a zone that uses freestanding @ in
  > RDATA is written to disk. Of course, this particular scenario rarely occurs
  > as it does not need to be written to disk when loaded on a primary and no
  > file exists if received over AXFR/IXFR. However, it may make sense to
  > implement optimistic compression of this form, and make it configurable.

* Class and type names are mutually exclusive in practice.
  RFC1035 states: The RR begins with optional TTL and class fields, ...
  Therefore, if a type name matches a class name, the parser cannot distinguish
  between the two in text representation and must resort to generic notation
  (RFC3597) or, depending on the RDATA format for the record type, a
  look-ahead may be sufficient. Realistically, it is highly likely that because
  of this, no type name will ever match a class name.

  > This means both can reside in the same table.

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

* RFC1035 specifies that the current origin should be restored after an
  $INCLUDE, but it is silent on whether the current domain name should also be
  restored. BIND 9 restores both of them. This could be construed as a
  deviation from RFC 1035, a feature, or both.

* RFC1035 states: and text literals can contain CRLF within the text.
  BIND, however, does not allow newlines in text (escaped or not). For
  performance reasons, we may adopt the same behavior as that would relieve
  the need to keep track of possibly embedded newlines.

* From: http://www.zytrax.com/books/dns/ch8/include.html (mentioned in chat)
  > Source states: The RFC is silent on the topic of embedded `$INCLUDE`s in
  > `$INCLUDE`d files - BIND 9 documentation is similarly silent. Assume they
  > are not permitted.

  All implementations, including BIND, allow for embedded `$INCLUDE`s.
  The current implementation is such that (embedded) includes are allowed by
  default. However, `$INCLUDE` directives can be disabled, which is useful
  when parsing from an untrusted source. There is also protection against
  cyclic includes.

  > There is no maximum to the amount of embedded includes (yet). NSD limits
  > the number of includes to 10 by default (compile option). For security, it
  > must be possible to set a hard limit.

* Should quoting of domain names be supported?
  RFC1035: The labels in the domain name are expressed as character strings
  and separated by dots.
  RFC1035: \<character-string\> is expressed in one or two ways:
  as \<contiguous\> (characters without interior spaces), or as \<quoted\>.

  However, quoted domain names are very uncommon. Implementations handle
  quoted names both in OWNER and RDATA very differently.

  * BIND
    * owner: yes, interpreted as quoted
      ```
      dig @127.0.0.1 A quoted.example.com.
      ```
      ```
      quoted.example.com.  xxx  IN  A  x.x.x.x
      ```
    * rdata: no, syntax error (even with `check-names master ignored;`)
  * Knot
    * owner: no, syntax error
    * rdata: no, syntax error
  * PowerDNS
    * owner: no, not interpreted as quoted
      ```
      pdnsutil list-zone example.com.
      ```
      ```
      "quoted".example.com  xxx  IN  A  x.x.x.x
      ```
    * rdata: no, not interpreted as quoted
      ```
      dig @127.0.0.1 NS example.com.
      ```
      ```
      example.com.  xxx  IN  NS  \"quoted.example.com.\".example.com.
      ```

  > The text "The labels in the domain name" can be confusing as one might
  > interpret that as stating that each label can individually can be quoted,
  > that is however not the case. NSD and BIND both print a syntax error if
  > such a construct occurs.

  > [libzscanner](https://github.com/CZ-NIC/knot/tree/master/src/libzscanner),
  > the (standalone) zone parser used by Knot seems mosts consistent.

* Should any domain names that are not valid host names as specified by
  RFC1123 section 2, i.e. use characters not in the preferred naming syntax
  as specified by RFC1035 section 2.3.1, be accepted? RFC2181 section 11 is
  very specific on this topic, but it merely states that labels may contain
  characters outside the set on the wire, it does not address what is, or is
  not, allowed in zone files.

  BIND's zone parser throws a syntax error for any name that is not a valid
  hostname unless `check-names master ignored;` is specified. Knot
  additionally accepts `-`, `_` and `/` according to
  [NOTES](https://github.com/CZ-NIC/knot/blob/master/src/libzscanner/NOTES).

  * [RFC1123 section 2](https://datatracker.ietf.org/doc/html/rfc1123#section-2)
  * [RFC1035 section 2.3.1](https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1)
  * [RFC2181 section 11](https://datatracker.ietf.org/doc/html/rfc2181#section-11)

* RFC1035 specifies two control directives "$INCLUDE" and "$ORIGIN". RFC2308
  specifies the "$TTL" directive. BIND additionally implements the "$DATE" and
  "$GENERATE" directives. Since "$" (dollar sign) is not reserved, both
  "$DATE" and "$GENERATE" (and "$TTL" before RFC2308) are considered valid
  domain names in other implementations (based on what is accepted for domain
  names, see earlier points). It seems "$" is better considered a reserved
  character (possibly limiting its special status to the start of the
  line), to allow for reliable extensibility in the future.

  > BIND seems to already throw an error if "$" is encountered, see
  > `lib/dns/master.c`. Presumably, the "$DATE" directive is written when the
  > zone is written to disk(?) In the code it is referred to as
  > __dump_time__ and later used to calculate __ttl_offset__.

* BIND10 had a nice writeup on zone files, kindly provided by Shane Kerr.
  [Zone File Loading Requirements on Wayback Machine](https://web.archive.org/web/20140928215002/http://bind10.isc.org:80/wiki/ZoneLoadingRequirements)
