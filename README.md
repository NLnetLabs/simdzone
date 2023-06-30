![Build Status](https://github.com/NLnetLabs/simdzone/actions/workflows/build-test.yml/badge.svg)
[![Coverity Status](https://scan.coverity.com/projects/27509/badge.svg)](https://scan.coverity.com/projects/nlnetlabs-simdzone)

simdzone: Parsing zone files really fast
========================================

Fast and standards compliant DNS zone parser library.

Zone files can become quite large and for some operators the existing parsers
leave something to be desired. simdjson demonstrates that applying SIMD
instructions for parsing structured text can quite significantly boost
performance. simdzone, whose name is a play on simdjson, aims to achieve a
similar performance boost for parsing zone data.

> Currently SSE4.2 and AVX2 are supported, a fallback is used otherwise.

> simdzone copies some code from the [simdjson][simdjson] project, with
> permission to use and distribute it under the terms of
> [The 3-Clause BSD License][bsd-3-clause].

[simdjson]: https://github.com/simdjson/simdjson
[bsd-3-clause]: https://opensource.org/license/bsd-3-clause/

## Results
Running `zone-bench` on my system (Intel Core i7-1065G7) against an older
`.com` zone file of 12482791271 bytes under Linux (Fedora 37).

GCC 12.2.1, release mode:
```
$ time ./zone-bench parse ../../zones/com.zone
Selected target haswell
Parsed 341535548 records

real    0m18.721s
user    0m17.503s
sys     0m1.181s
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
