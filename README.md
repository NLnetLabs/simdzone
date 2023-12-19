![Build Status](https://github.com/NLnetLabs/simdzone/actions/workflows/build-test.yml/badge.svg)
[![Coverity Status](https://scan.coverity.com/projects/27509/badge.svg)](https://scan.coverity.com/projects/nlnetlabs-simdzone)

# simdzone: Parsing zone files really fast

Fast and standards compliant DNS presentation format parser.

DNS resource records (RRs) can be expressed in text form using the
presentation format. The format is most frequently used to define a zone in
master files, more commonly known as zone files, and is best considered a
tabular serialization format with provisions for convenient editing.

The format is originally defined in [RFC1035 section 5][rfc1035-section-5] and
[RFC1034 section 3.6.1][rfc1034-section-3-6-1], but as the DNS is
intentionally extensible, the format has been extended over time too.

This project provides a lightning fast presentation format deserializer (and
serializer eventually) for other projects to leverage. e.g. [NSD][nsd], will
use it to read zone files and serialized zone transfers.

## Motivation
Zone files can become quite large (.com ~24G, .se ~1.3G) and the parser in
NSD left something to be desired. simdjson demonstrates that applying SIMD
instructions for parsing structured text can significantly boost performance.
simdzone, whose name is a play on [simdjson][simdjson], aims to achieve a
similar performance boost for parsing zone data.

> Currently SSE4.2 and AVX2 are supported, a fallback is used otherwise.

> simdzone copies some code from the [simdjson][simdjson] project, with
> permission to use and distribute it under the terms of
> [The 3-Clause BSD License][bsd-3-clause].

[rfc1035-section-5]: https://datatracker.ietf.org/doc/html/rfc1035#section-5
[rfc1034-section-3-6-1]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.1
[nsd]: https://nlnetlabs.nl/projects/nsd/about/
[simdjson]: https://github.com/simdjson/simdjson
[bsd-3-clause]: https://opensource.org/license/bsd-3-clause/

## Results
Running `zone-bench` on my system (Intel Core i7-1065G7) against an older
`.com` zone file of 12482791271 bytes under Linux (Fedora 39).

clang version 17.0.6, release mode:
```
$ time ./zone-bench parse ../../zones/com.zone
Selected target haswell
Parsed 341535548 records

real    0m13.533s
user    0m12.355s
sys     0m1.160s
```

There are bound to be bugs and quite possibly smarter ways of implementing
some operations, but the results are promising.

## Compiling
Make sure the following tools are installed:
  * C toolchain (the set of tools to compile C code)
  * [cmocka](https://cmocka.org/) (if configured with `-DBUILD_TESTING=on`)
  * [Doxygen](https://www.doxygen.nl/) (if configured with `-DBUILD_DOCUMENTATION=on`)

To compile in release mode:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ cmake --build .
```

To compile in debug mode with testing:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=on ..
$ cmake --build .
```

To build documentation:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_DOCUMENTATION=on ..
$ cmake --build . --target doxygen
```

## Contributing
Contributions in any way, shape or form are very welcome! Please see
[CONTRIBUTING.md](CONTRIBUTING.md) to find out how you can help.
