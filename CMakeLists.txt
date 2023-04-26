#
# Copyright (c) 2022-2023, NLnet Labs. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
cmake_minimum_required(VERSION 3.10)
project(
  simdzone
  LANGUAGES C
  VERSION 0.1.0
  DESCRIPTION "Fast and standards compliant DNS zone parser")

set(CMAKE_C_STANDARD 99)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

if(CMAKE_VERSION VERSION_LESS 3.12)
  # GENERATE_EXPORT_HEADER requires a C++ compiler up to version 3.12
  enable_language(CXX)
endif()

if(CMAKE_VERSION VERSION_LESS 3.24)
  # COMPILE_WARNING_AS_ERROR property was added in version 3.24. Mimic the
  # option in prior versions.
  option(CMAKE_COMPILE_WARNING_AS_ERROR "Treat compiler warnings as errors." OFF)
  if(CMAKE_COMPILE_WARNING_AS_ERROR)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
      add_compile_options(-Werror)
    elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
      add_compile_options(/WX)
    endif()
  endif()
endif()

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE
      STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Building the testing tree is enabled by including CTest, but as it is not
# strictly required to build the product itself, switch to off by default.
option(BUILD_TESTING "Build the testing tree." OFF)
option(BUILD_DOCUMENTATION "Build documentation." OFF)

include(CheckIncludeFile)
include(CheckCCompilerFlag)
include(GenerateExportHeader)
include(GNUInstallDirs)
include(CTest)

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_compile_options(
    -Wall -Wextra -Wconversion -Wunused -Wmissing-prototypes
    -Winfinite-recursion -Wassign-enum -Wcomma -Wdocumentation
    -Wstrict-prototypes -Wconditional-uninitialized -Wshadow)
  if(CMAKE_GENERATOR STREQUAL "Ninja")
    add_compile_options(-Xclang -fcolor-diagnostics)
  endif()
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(
    -Wall -Wextra -pedantic)
  if(CMAKE_GENERATOR STREQUAL "Ninja")
    add_compile_options(-fdiagnostics-color=always)
  endif()
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
  add_compile_options(/W3)
endif()

set(ANALYZER "" CACHE STRING "Analyzer to enable on the build.")
if(ANALYZER)
  # GCC and Visual Studio offer builtin analyzers. Clang supports static
  # analysis through separate tools, e.g. Clang-Tidy, which can be used in
  # conjunction with other compilers too. Specifying -DANALYZER=on enables
  # the builtin analyzer for the compiler, enabling clang-tidy in case of
  # Clang. Specifying -DANALYZER=clang-tidy always enables clang-tidy.
  string(REPLACE " " "" ANALYZER "${ANALYZER}")
  string(TOLOWER "${ANALYZER}" ANALYZER)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND ANALYZER STREQUAL "on")
    set(ANALYZER "clang-tidy")
  endif()

  if(ANALYZER STREQUAL "clang-tidy")
    # Clang-Tidy is an extensible tool that offers more than static analysis.
    # https://clang.llvm.org/extra/clang-tidy/checks/list.html
    message(STATUS "Enabling analyzer: clang-tidy")
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=-*,clang-analyzer-*,-clang-analyzer-security.insecureAPI.strcpy,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling")
    if(CMAKE_COMPILE_WARNING_AS_ERROR)
      set(CMAKE_C_CLANG_TIDY "${CMAKE_C_CLANG_TIDY};--warnings-as-errors=*")
    endif()
  elseif(ANALYZER STREQUAL "on")
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "10")
        message(STATUS "Enabling analyzer: GCC")
        # -Wanalyzer-malloc-leak generates lots of false positives
        add_compile_options(-fanalyzer -Wno-analyzer-malloc-leak)
      endif()
    endif()
  endif()
endif()

set(SANITIZER "" CACHE STRING "Sanitizers to enable on the build.")
if(SANITIZER)
  string(REGEX REPLACE " " "" SANITIZER "${SANITIZER}")
  string(REGEX REPLACE "[,;]+" ";" SANITIZER "${SANITIZER}")
  foreach(san ${SANITIZER})
    if(san STREQUAL "address")
      add_compile_options("-fno-omit-frame-pointer")
      add_link_options("-fno-omit-frame-pointer")
    endif()
    if(san AND NOT san STREQUAL "none")
      message(STATUS "Enabling sanitizer: ${san}")
      add_compile_options("-fsanitize=${san}")
      add_link_options("-fsanitize=${san}")
    endif()
  endforeach()
endif()

add_library(zone STATIC)
if(WIN32)
  target_link_libraries(zone INTERFACE ws2_32)
endif()

generate_export_header(
  zone BASE_NAME ZONE EXPORT_FILE_NAME include/zone/export.h)

target_include_directories(
  zone PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
       PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
               $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

target_sources(zone PRIVATE
  src/zone.c
  src/types.c
  src/table.c
  src/log.c
  src/parser.c
  src/lexer.c
  src/heap.c
  src/generic/base16.c
  src/generic/base32.c
  src/generic/base64.c
  src/fallback/parser.c)

add_executable(zone-bench src/bench.c src/fallback/bench.c)
target_include_directories(
  zone-bench PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
                     $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
target_link_libraries(zone-bench PRIVATE zone)

check_include_file(unistd.h HAVE_UNISTD_H)
if(NOT HAVE_UNISTD_H)
  target_include_directories(
    zone-bench PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/compat>)
  target_sources(zone-bench PRIVATE compat/getopt.c)
endif()

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
    set(HAVE_WESTMERE TRUE)
    set_source_files_properties(
      src/westmere/parser.c PROPERTIES COMPILE_FLAGS "-march=westmere")
    target_sources(zone PRIVATE src/westmere/parser.c)
    set_source_files_properties(
      src/westmere/bench.c PROPERTIES COMPILE_FLAGS "-march=westmere")
    target_sources(zone-bench PRIVATE src/westmere/bench.c)
  endif()

  if(HAVE_IMMINTRIN_H AND HAVE_MARCH_HASWELL)
    set(HAVE_HASWELL TRUE)
    set_source_files_properties(
      src/haswell/parser.c PROPERTIES COMPILE_FLAGS "-march=haswell")
    target_sources(zone PRIVATE src/haswell/parser.c)
    set_source_files_properties(
      src/haswell/bench.c PROPERTIES COMPILE_FLAGS "-march=haswell")
    target_sources(zone-bench PRIVATE src/haswell/bench.c)
  endif()
endif()


# Autoconf is supported for easy inclusion of simdzone in NSD. To avoid having
# to maintain multiple configuration headers, instead of using configure_file,
# read config.h.in and replace occurences of "#undef XYZ".
file(READ src/config.h.in template)

set(expression "(^|\n)[ \t]*#[ \t]*undef[ \t]([a-zA-Z0-9_]+)[ \t]*(\n|$)")
string(REGEX MATCHALL "${expression}" matches "${template}")
foreach(match ${matches})
  if(match MATCHES "${expression}")
    set(prefix "${CMAKE_MATCH_1}")
    set(variable "${CMAKE_MATCH_2}")
    set(suffix "${CMAKE_MATCH_3}")
    if(NOT DEFINED ${variable} OR
       ${variable} MATCHES "^[Ff][Aa][Ll][Ss][Ee]$" OR
       ${variable} MATCHES "^[Oo][Ff][Ff]")
      set(replace "${prefix}/* #undef ${variable} */${suffix}")
    elseif(${variable} MATCHES "^[Tt][Rr][Uu][Ee]$" OR
           ${variable} MATCHES "^[Oo][Nn]$")
      set(replace "${prefix}#define ${variable} 1${suffix}")
    elseif(${variable} MATCHES "^[01234567890]+$")
      set(replace "${prefix}#define ${variable} ${${variable}}${suffix}")
    else()
      set(replace "${prefix}#define ${variable} \"${${variable}}\"")
    endif()
  endif()
  string(REPLACE "${match}" "${replace}" template "${template}")
endforeach()

file(GENERATE OUTPUT config.h CONTENT "${template}")


if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

if(BUILD_DOCUMENTATION)
  set(DOXYGEN_GENERATE_HTML YES)
  set(DOXYGEN_GENERATE_XML NO)
  set(DOXYGEN_STRIP_FROM_PATH "include")
  set(DOXYGEN_MACRO_EXPANSION YES)
  set(DOXYGEN_PREDEFINED
    "ZONE_EXPORT=")
  # https://datatracker.ietf.org/doc/rfc<xxx>/
  # https://datatracker.ietf.org/doc/draft-ietf-<xxx>-<yyy>/
  set(DOXYGEN_ALIASES
    "rfc{1}=\"<a href='https://datatracker.ietf.org/doc/rfc\\1/'>[RFC\\1]</a>\""
    "draft{2}=\"<a href='https://datatracker.ietf.org/doc/draft-ietf-\\1-\\2/'>[draft-ietf-\\1-\\2]</a>\""
    "obsolete=<b>(OBSOLETE)</b>"
    "experimental=<b>(EXPERIMENTAL)</b>")
  set(DOXYGEN_VERBATIM_VARS DOXYGEN_ALIASES)
  find_package(Doxygen REQUIRED)
  doxygen_add_docs(doxygen include)
endif()
