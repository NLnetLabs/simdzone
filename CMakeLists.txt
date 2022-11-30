cmake_minimum_required(VERSION 3.18)
project(
  simdzone
  LANGUAGES C
  VERSION 0.1.0
  DESCRIPTION "Fast and standards compliant DNS zone file parser")

include(CheckIncludeFile)
include(CheckCCompilerFlag)

add_executable(simdzone src/zone.c)
target_include_directories(
  simdzone PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
                  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

# Multiple instruction sets may be supported by a specific architecture.
# e.g. x86_64 may (or may not) support any of SSE42, AVX2 and AVX-512. The
# best instruction set is automatically selected at runtime, but the compiler
# may or may not support generating code for an instruction set

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" architecture)

# FIXME: probably need an option to select which implementations to use(?)
# FIXME: likely too GCC/Clang specific

if(architecture STREQUAL "x86_64" OR architecture STREQUAL "amd64")
  check_include_file("immintrin.h" HAVE_IMMINTRIN_H)
  check_c_compiler_flag("-march=westmere" HAVE_MARCH_WESTMERE)
  check_c_compiler_flag("-march=haswell" HAVE_MARCH_HASWELL)

  if(HAVE_IMMINTRIN_H AND HAVE_MARCH_WESTMERE)
    set(ZONE_SUPPORTS_WESTMERE TRUE)
    set_source_files_properties(
      src/westmere/parser.c PROPERTIES COMPILE_FLAGS "-march=westmere")
    target_sources(simdzone PRIVATE src/westmere/parser.c)
  endif()

  if(HAVE_IMMINTRIN_H AND HAVE_MARCH_HASWELL)
    set(ZONE_SUPPORTS_HASWELL TRUE)
    set_source_files_properties(
      src/haswell/parser.c PROPERTIES COMPILE_FLAGS "-march=haswell")
    target_sources(simdzone PRIVATE src/haswell/parser.c)
  endif()
endif()

configure_file(config.h.in config.h)
