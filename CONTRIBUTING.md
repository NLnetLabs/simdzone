# Contributing to simdzone

The simdzone library is open source and made available under the permissive
3-clause BSD license.

Contributions are very much appreciated.


## Source layout

`include` contains only headers required for consumption of the library.

`src` contains the implementation and internal headers.

The layout of `src` is (of course) inspired by the layout in simdjson. The
structure is intentionally simple and without (too much) hierarchy, but as
simdzone has very architecture specific code to maximize performance, there
are some caveats.

Processors may support multiple instruction sets. e.g. x86\_64 may support
SSE4.2, AVX2 and AVX-512 instruction sets depending on the processor family.
The preferred implementation is automatically selected at runtime. As a result,
code may need to be compiled more than once. To improve code reuse, shared
logic resides in headers rather than source files and is declared static to
avoid name clashes. Bits and pieces are then mixed and matched in a
`src/<arch>/parser.c` compilation target to allow for multiple implementations
to co-exist.

Sources and headers common to all architectures that do not implement parsing
for a specific data-type reside directly under `src`. Code specific to an
architecture resides in a directory under `src`, e.g. `haswell` or `fallback`.
`src/generic` contains scanner and parser code common to all implementations,
but leans towards code shared by SIMD implementations.

For example, SIMD-optimized scanner code resides in `src/generic/scanner.h`,
abstractions for intrinsics reside in e.g. `src/haswell/simd.h` and `lex(...)`,
which is used by all implementations, is implemented in `src/lexer.h`.
A fallback scanner is implemented in `src/fallback/scanner.h`.

A SIMD-optimized type parser is implemented in `src/generic/type.h`, a fallback
type parser is implemented in `src/fallback/type.h`. Future versions are
expected to add more optimized parsers for specific data types, even parsers
that are tied to a specific instruction set. The layout accomodates these
scenarios. e.g. an AVX2 optimized parser may reside in `src/haswell/<type>.h`,
an SSE4.2 optimized parser may reside in `src/westmere/<type>.h`, etc.

## Symbol visibility

All exported symbols, identifiers, etc must be prefixed with `zone_`, or
`ZONE_` for macros. Non-exported symbols are generally not prefixed. e.g.
`lex(...)` and `scan(...)` are declared static and as such are not required to
be prefixed.
