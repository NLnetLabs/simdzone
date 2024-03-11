.. include:: links.rst

###################
Presentation format
###################

DNS resource records (RRs) can be expressed in text form using the DNS
presentation format. The format is originally defined in
:rfc:`1035#section-5.1` and :rfc:`1034#section-3.6.1` and is most
frequently used to define a zone in master files, more commonly known as
zone files. The term "presentation format" is officially established in
:rfc:`8499#section-5`.

The presentation format is a concise tabular serialization format with
provisions for convenient editing. The DNS is intentionally extensible and
many RFCs define additional types and the typical representation for the
corresponding RDATA sections. Consequently, the presentation format is not
defined by one single specification, but rather many specifications.

The presentation format is NOT context-free and correct interpretation of the
specification(s) is rather dependent on extensive knowledge of the DNS.

.. note::
   This document is meant to be a concise source on interpretation of the
   presentation format, but is still very much a work in progress. Please
   consider contributing if anything is unclear or incorrect.

Format
======

.. note:: Modified text from :rfc:`1035#section-5.1`

The presentation format defines a number of entries. Entries are predominantly
line-oriented, though parentheses can be use to continue a list of items
across a line boundary, and text literals can contain CRLF within the text.
Any combination of tabs and spaces act as a delimiter between the separate
items that make up an entry. The end of any line can end with a comment.
Comments start with a ``;`` (semicolon).

The following entries are defined:

    <blank>[<comment>]

    $ORIGIN <domain-name> [<comment>]

    $INCLUDE <file-name> [<domain-name>] [<comment>]

    $TTL <TTL> [<comment>]

    <domain-name><rr> [<comment>]

    <blank><rr> [<comment>]

Blank lines, with or without comments, are allowed anywhere in the file.

Three control entries are defined: $ORIGIN, $INCLUDE and $TTL (defined in
:rfc:`2308#section-4`). $ORIGIN is followed by a domain name, and resets the
current origin for relative domain names to the stated name. $INCLUDE inserts
the named file into the current file, and may optionally specify a domain name
that sets the relative domain name origin for the included file. $INCLUDE may
also have a comment.  Note that a $INCLUDE entry never changes the relative
origin of the parent file, regardless of changes to the relative origin made
within the included file. $TTL is followed by a decimal integer, and resets
the default TTL for RRs which do not explicitly include a TTL value.

The last two forms represent RRs. If an entry for an RR begins with a
``<blank>``, then the RR is assumed to be owned by the last stated owner. If
an RR entry begins with a ``<domain-name>``, then the owner name is reset.

``<rr>`` contents take one of the following forms:

    [<TTL>] [<class>] <type> <RDATA>

    [<class>] [<TTL>] <type> <RDATA>

The RR begins with optional TTL and class fields, followed by a type and
RDATA field appropriate to the type and class.  Class and type use the
standard mnemonics, TTL is a decimal integer.  Omitted class and TTL
values are default to the last explicitly stated values.  Since type and
class mnemonics are disjoint, the parse is unique.  (Note that this
order is different from wire format order; the given order allows easier
parsing and defaulting.)

<domain-name>s make up a large share of the data in the master file.
The labels in the domain name are expressed as character strings and
separated by dots.  Quoting conventions allow arbitrary characters to be
stored in domain names.  Domain names that end in a dot are called
absolute, and are taken as complete.  Domain names which do not end in a
dot are called relative; the actual domain name is the concatenation of
the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
an argument to the master file loading routine.  A relative name is an
error when no origin is available.

<character-string> is expressed in one or two ways: as a contiguous set of
characters without interior spaces, or as a string beginning with a ``"``
and ending with a ``"``.  Inside a ``"`` delimited string any character can
occur, except for a ``"`` itself, which must be quoted using ``\\``
(backslash).

Because these files are text files several special encodings are
necessary to allow arbitrary data to be loaded.  In particular:

                of the root.

@               A free standing @ is used to denote the current origin.

\X              where X is any character other than a digit (0-9), is
                used to quote that character so that its special meaning
                does not apply.  For example, "\." can be used to place
                a dot character in a label.

\DDD            where each D is a digit is the octet corresponding to
                the decimal number described by DDD.  The resulting
                octet is assumed to be text and is not checked for
                special meaning.

( )             Parentheses are used to group data that crosses a line
                boundary.  In effect, line terminations are not
                recognized within parentheses.

;               Semicolon is used to start a comment; the remainder of
                the line is ignored.


Handling of Unknown DNS Resource Record (RR) Types
--------------------------------------------------

The intentional extensibility in the DNS may lead to software implementations
lagging behind in support. :rfc:`3597#section-5` introduces generic
notations to represent unknown types, classes and the corresponding RDATA in
text form.

.. note:: Modified text from :rfc:`3597#section-5`.

The type field for an unknown RR type is represented by the word ``TYPE``
immediately followed by the decimal RR type code, with no intervening
whitespace.  In the class field, an unknown class is similarly represented
as the word ``CLASS`` immediately followed by the decimal class code.

This convention allows types and classes to be distinguished from each other
and from TTL values, allowing both <rr> forms to be unambiguously parsed.

    [<TTL>] [<class>] <type> <RDATA>

    [<class>] [<TTL>] <type> <RDATA>


The RDATA section of an RR of unknown type is represented as a sequence of
white space separated words as follows:

    The special token ``\\#`` (a backslash immediately followed by a hash
    sign), which identifies the RDATA as having the generic encoding
    defined herein rather than a traditional type-specific encoding.

    An unsigned decimal integer specifying the RDATA length in octets.

    Zero or more words of hexadecimal data encoding the actual RDATA field,
    each containing an even number of hexadecimal digits.

If the RDATA is of zero length, the text representation contains only the
``\\#`` token and the single zero representing the length.

Even though an RR of known type represented in the ``\#`` format is effectively
treated as an unknown type for the purpose of parsing the RDATA text
representation, all further processing by the server MUST treat it as a
known type and take into account any applicable type-specific rules regarding
compression, canonicalization, etc.


Service Binding and Parameter Specification via the DNS
-------------------------------------------------------

:rfc:`9460` introduces a key-value syntax to the presentation format for
the ``SVCB`` and ``HTTPS`` type (initially). The addition is a major change
for implementors of presentation format parsers.

.. note::
   Write (or copy) a section on the format from :rfc:`9460#section-2.1`.

The RFC specifies a number of initial Service Parameter Keys (SvcParamKeys).
IANA maintains these and additional keys in the Service Parameter Keys
(SvcParamKeys) registry in the |url::dns-svcb| category.

alpn and no-default-alpn
^^^^^^^^^^^^^^^^^^^^^^^^

:rfc:`9460#section-7.1.1` specifies the ``alpn`` and ``no-default-alpn``
SvcParamKeys. The ``alpn`` SvcParamKey takes a comma-separated list of
Application-Layer Protocol Negotiation (ALPN) Protocol IDs (maintained
by IANA in the |url::tls-extensiontype-values| category), the syntax for which
is defined in :rfc:`9460#appendix-A.1`.

A problem arises when items in the comma-separated list may contain a ``,``
(comma) or ``\\`` (backslash). :rfc:`9460#section-2.1` specifies
SvcParamValue to be a ``char-string`` and some implementations (incorrectly)
unescape ``char-string`` during the scanner stage. Consequently, the fact that
a character is ``escaped`` (``\000`` or ``\X``) is lost to the comma-separated
list parser. None of the registered protocol identifiers (currently) contains
a ``,`` (comma) and the specification dismisses the issue in the interest of
progress.

:rfc:`9460#appendix-A.1` specifies ``simple-comma-separated``, for lists of
items that cannot contain either of the aforementioned characters, and
``comma-separated`` for lists of items that can. The specification overlooks
that ``alpn``, or comma-separated lists, are encoded on the wire as a sequence
of strings, or a sequence of length octet followed by a maximum of 255 data
octets. A name server writing a transfer to disk in plain text can therefore
not encode data using the ``simple-comma-separated`` scheme.

The specification contradicts itself in :rfc:`9460#section-7.1.1` by
stating that presentation format parsers MAY simply disallow the ``,`` and
``\\`` characters in ALPN IDs instead of implementing the value-list escaping
procedure by relying on the opaque key format (e.g., ``key1=\002h2``) in the
event that these characters are needed. Since SvcParamValue is defined to be
``char-string``, the problem persists. To implementations that unescape during
the scanner stage, the escape sequence is still lost and implementations that
unescape during the parser stage did not have the problem to start with.

:rfc:`9460` incorrectly assumes that ``char-string`` presents text.
Programming languages typically classify a token as string if it is quoted,
an identifier or keyword if it is a contiguous set of characters, etc.
Unescaping is then typically done by the scanner because tokens can be
classified during that stage. The presentation format defines basic syntax to
identify tokens, but as the format is NOT context-free and intentionally
existensible, the token can only be classified during the parser stage. Simply
put, ``char-string`` in the presentation format cannot be unescaped during the
scanner stage as the scanner does not know the type of information the
``char-string`` presents. Domain names are a prime example.

The RR ``foo. NS \.`` defines ``bar\.`` as a relative domain name. The ``\\``
(backslash) is important because it signals that the trailing dot does not
serve as a label separator.

.. note::
   This issue has been `discussed 
   <https://mailarchive.ietf.org/arch/msg/dnsop/SXnlsE1B8gmlDjn4HtOo1lwtqAI/>`_ 
   on the DNSOP IETF mailing list.

As BIND, Knot and NSD implement double escaping, so does |project| even though
the behavior is incorrect.

