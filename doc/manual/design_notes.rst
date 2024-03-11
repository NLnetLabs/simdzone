.. include:: links.rst

.. _simdjson paper: https://arxiv.org/abs/1902.08318

###############
Notes on design
###############

|project| draws inspiration from the |url::simdjson| project. The simdjson
project demonstrates that throughput can be much improved using single
instruction, multiple data (SIMD) instructions found in modern processors.

The `simdjson paper`_ describes the technical details in great depth and is
definitely worth reading first. A concise recap to understand where |project|
is different.

|project| operates in two stages. simdjson first allocates enough memory to
store the document and the worst-case number of indexes. The first stage, or
indexing stage, operates on 64-byte blocks and uses vectorized classification
to identify structural characters. Relative indexes are stored in a bitmask
and binary logic is used to identify strings and sequences of non-structural
characters. Using more binary logic, the indexes of all structural characters
and the first character of each sequence is retained. Fast population and
trailing zero count instructions found in modern processors are then used to
write out indexes in order to a vector, dubbed "tape" by simdjson.

The second stage iterates all indexes and parses booleans, integers,
floating-point values, strings and any structurals, constructing the Document
Object Model (DOM) on-the-fly. SIMD instructions are used to avoid branching
as much as possible.

|project| adheres to most basic principles, but there are some important
modifications due to differences between both formats.

.. note::
    This document is meant to capture important notes on the inner workings
    of |project|, it is currently work-in-progress.


Buffered operation
------------------

|project| was created to work with large DNS zones more conveniently.

- ``.com`` (~161 million domains, ~24GB in size)
- ``.nl`` (~6.3 million domains)
- ``.se`` (~1.4 million domains, ~1.2GB in size)

Keeping all data in memory for parsing and serving means a minimum of ~50GB of
memory is required for loading ``.com``. Not counting the structures to retain
ordering and hierarchy, which typically require more memory than the data.
As a result, |project| retains the notion of a tape and two separate stages,
but indexing happens on-the-fly as required.

On-the-fly indexing is also required because the DNS presentation format
supports the ``$INCLUDE`` control directive. If such a control directive is
encountered, the parser is expected to parse the data in the specified file
before parsing the remaining contents in the current file. Tape operation is
therefore managed on a per file base.

On-the-fly indexing is a good tradeoff, but does introduce some complexity
with regards to handling partial tokens.


Comments
--------

|project| uses much of same classification algorithm, with one caveat. The
DNS presentation format supports comments, which makes classification a bit
more difficult. A scalar loop is used to correctly discard semicolons within
strings and quotes within comments.


Delimiters
----------

The DNS presentation format is less strict. JSON requires strings to be
quoted, the same is not true for the DNS presentation format. Strings in TXT
records maybe written as a set of contiguous characters without interior
spaces or as a string beginning with a ``"`` (quote) and ending with a ``".``
:RFC:`9460` introduces SvcParams, the value of which may be quoted or not. To
avoid writing more than one parser for types, store the length of the token
so that the parser does not have to scan for the delimiter.

Rather than storing the data once and determine by inspection of delimiting
index if tape must be advanced again, use two separate tapes. Since the format
is tabular, master files rarely contain structural characters other than
newlines, therefore the overhead is small. The same logic is used when writing
indexes to the tapes.


Predictability
--------------

Once the RTYPE is known, the RDATA layout is more-or-less predictable. This
knowledge can be leveraged to expect the right token and fallback to a slower
path. That way the optimized path can be inlined while the slower path resides
in a function. Binary size hereby reduced as much as possible while token
extraction is as fast as can be. This knowledge also allows for calling the
correct parser functions in order, eliminating the need for more calling more
generalized parser functions based on a descriptor table.
