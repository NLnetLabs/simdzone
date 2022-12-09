simdzone : Parsing zone files really fast
=========================================

Fast and standards compliant DNS zone file parser library.

Zone files can become quite large and for some operators the parser included
with NSD leaves something to be desired. Replacing the Flex and Bison based
parser with a hand written one, should speedup loading of zone files
significantly. simdjson demonstrates that applying SIMD instructions for
parsing structured text can quite significantly boost performance too.
simdzone, whose name is a play on simdjson, is a simple research project to
determine if a similar performance boost can be achieved for parsing zone
files.

Currently, only tokenization is implemented and AVX2 is required.

The project uses quite some code from the simdjson project. That code remains
licensed under the Apache-2.0 license. Credits and copyright reside with the
original authors.

## Early results
Running `simdzone` on my system (Intel Core i7-1065G7) against an older
`.com` zone file of 12482791271 bytes under Linux (Fedora 36).

GCC 12.2.1, release mode:
```
time ./simdzone ../../com.zone
saw 1404916636 tokens

real    0m8.661s
user    0m7.432s
sys     0m1.216s
```

Clang 14.0.5, release mode:
```
time ./simdzone ../../com.zone
saw 1404916636 tokens

real    0m8.449s
user    0m7.321s
sys     0m1.118s
```

There are bound to be bugs and quite possibly smarter ways of implementing
some operations, but the results are promising.


## Compiling
Make sure the following tools are installed:
  * C toolchain (the set of tools to compile C code)
  * [cmocka](https://cmocka.org/) (if configured with `-DBUILD_TESTING=on`

To compile in release mode:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ cmake --build .
```

To compile in debug mode:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ cmake --build .
```

## Notes
Some of the algorithms used in simdjson fit nicely with zone files, but it is
certainly not a clean fit. The biggest challenge is the fact that zone files
may contain both comment and quoted sections. Each of which may contain the
starting character for the other. Therefore, just discarding escaped quotes
and applying carry-less multiplication does not work. For now, the problem
is solved using a loop and some bit bashing, but a better solution may exists.

simdjson stores the start of each token in a vector and visits each element
identified in a second stage. The same logic cannot be used for zone files
because each field can be delimited in multiple ways. Zone files have no
cleanly defined types as JSON does. Therefore, two indexes are stored for
each non-structural token. When reading back the indexes, the two are
combined to return an offset and a length. For quoted fields, the second index
is discarded, for contiguous fields, the second index is read again in the
next iteration and discarded if it points towards a whitespace character.
This introduces some overhead in the scanning stage, but may speedup the
parsing stage as most data can then simply be copied instead of iterating
over it again.

Zone files may include other zone files, so multiple states may exist
concurrently. To solve this, the indexing state is kept per zone file.

Zone files may be huge. To avoid having the data in memory multiple times
(active database, reload database and parser), a fixed buffer and tape are
applied. This has some performance implications (2-3 seconds in my tests), but
in my opinion it is the right choice. Maybe a better solution can be thought
of in the future, but for now it seems like the right tradeof.

## Plans
The scanner now returns tokens including the length. This allows the parser
to simply copy the data and leverage SIMD operations where possible. There is
quite a lot research in applying SIMD operations for base64 decoding and it
seems converting domain names to wire format can benefit from SIMD treatment
as well.

Apart from that, the current implementation applies a table to lookup the
parse function for each field. I have a hunch that instead of generating a
table we can benefit from simply generating the parse function for each
record type instead. That will probably speedup the process a lot.
