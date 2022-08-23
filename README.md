# Zone

Fast and standards compliant DNS zone file parser library.

This project provides a standalone zone parsing library, which may or may not
be used in the various DNS projects developed and maintained by NLnet Labs.
Upon completion, it may or may not be further maintained as part of another
project.

Currently it provides an incomplete and rough (yet working) library for
parsing zone files. The `$INCLUDE` control is not yet implemented and there
are much record types that are not yet supported, though the latter
may be solved by simply adding it to [type.stanzas](src/type.stanzas), from
which all descriptors are generated.

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

To compile in debug mode and run tests:
```
$ cd zone-parser
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=on -DANALYZER=clang-tidy ..
$ cmake --build .
$ ctest -T test
```
