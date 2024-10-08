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
  DESCRIPTION "Fast and standards compliant DNS presentation format parser")

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

option(WESTMERE "Build Westmere (SSE4.2) kernel for x86_64" ON)
option(HASWELL "Build Haswell (AVX2) kernel for x86_64" ON)

if(CMAKE_VERSION VERSION_LESS 3.20)
  # CMAKE_<LANG>_BYTE_ORDER was added in version 3.20. Mimic the option in
  # prior versions.
  include(TestBigEndian)
  test_big_endian(BIG_ENDIAN)
  if(BIG_ENDIAN)
    set(CMAKE_C_BYTE_ORDER "BIG_ENDIAN")
  else()
    set(CMAKE_C_BYTE_ORDER "LITTLE_ENDIAN")
  endif()
endif()
include(CheckIncludeFile)
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckSymbolExists)
include(GenerateExportHeader)
include(CMakePackageConfigHelpers)
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

if(MINGW)
  # Require at least Windows 7
  add_definitions(-D_WIN32_WINNT=_WIN32_WINNT_WIN7)
  add_definitions(-DNTDDI_VERSION=NTDDI_WIN7)
  add_definitions(-D__USE_MINGW_ANSI_STDIO=1) # prefer C99 conformance
  # Do not prefix libraries with "lib"
  set(CMAKE_SHARED_LIBRARY_PREFIX "")
  set(CMAKE_STATIC_LIBRARY_PREFIX "")
endif()

add_library(zone)

generate_export_header(
  zone BASE_NAME ZONE EXPORT_FILE_NAME include/zone/export.h)

target_include_directories(
  zone PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
              $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_sources(zone PRIVATE
  src/zone.c src/fallback/parser.c)

add_executable(zone-bench src/bench.c src/fallback/bench.c)
target_include_directories(
  zone-bench PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
                     $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
target_link_libraries(zone-bench PRIVATE zone)

check_include_file(endian.h HAVE_ENDIAN_H)
check_include_file(sys/endian.h HAVE_SYS_ENDIAN_H)
check_include_file(unistd.h HAVE_UNISTD_H)
set(ENDIAN_INCLUDES "endian.h")
if(HAVE_SYS_ENDIAN_H)
  set(ENDIAN_INCLUDES "${ENDIAN_INCLUDES};sys/endian.h")
endif()
check_symbol_exists(bswap16 ${ENDIAN_INCLUDES} HAVE_DECL_BSWAP16)
check_symbol_exists(bswap32 ${ENDIAN_INCLUDES} HAVE_DECL_BSWAP32)
check_symbol_exists(bswap64 ${ENDIAN_INCLUDES} HAVE_DECL_BSWAP64)

set(CMAKE_REQUIRED_DEFINITIONS "-D_DEFAULT_SOURCE=1")
check_symbol_exists(getopt "stdlib.h;unistd.h" HAVE_GETOPT)
unset(CMAKE_REQUIRED_DEFINITIONS)
if(NOT HAVE_GETOPT)
  target_include_directories(
    zone-bench PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/compat>)
  target_sources(zone-bench PRIVATE compat/getopt.c)
endif()

if(NOT WIN32)
  # _fullpath is used on Microsoft Windows.
  set(CMAKE_REQUIRED_DEFINITIONS "-D_DEFAULT_SOURCE=1")
  check_symbol_exists(realpath "stdlib.h" HAVE_REALPATH)
  unset(CMAKE_REQUIRED_DEFINITIONS)
  if(NOT HAVE_REALPATH)
    message(FATAL_ERROR "realpath is not available")
  endif()
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
    set(CMAKE_REQUIRED_FLAGS "-march=westmere")
    file(READ cmake/westmere.test.c westmere_test)
    check_c_source_compiles("${westmere_test}" HAVE_WESTMERE)
    unset(CMAKE_REQUIRED_FLAGS)
    if (HAVE_WESTMERE)
      set_source_files_properties(
        src/westmere/parser.c PROPERTIES COMPILE_FLAGS "-march=westmere")
      target_sources(zone PRIVATE src/westmere/parser.c)
      set_source_files_properties(
        src/westmere/bench.c PROPERTIES COMPILE_FLAGS "-march=westmere")
      target_sources(zone-bench PRIVATE src/westmere/bench.c)
    endif()
  endif()

  if(HAVE_IMMINTRIN_H AND HAVE_MARCH_HASWELL)
    set(CMAKE_REQUIRED_FLAGS "-march=haswell")
    file(READ cmake/haswell.test.c haswell_test)
    check_c_source_compiles("${haswell_test}" HAVE_HASWELL)
    unset(CMAKE_REQUIRED_FLAGS)
    if (HAVE_HASWELL)
      set_source_files_properties(
        src/haswell/parser.c PROPERTIES COMPILE_FLAGS "-march=haswell")
      target_sources(zone PRIVATE src/haswell/parser.c)
      set_source_files_properties(
        src/haswell/bench.c PROPERTIES COMPILE_FLAGS "-march=haswell")
      target_sources(zone-bench PRIVATE src/haswell/bench.c)
    endif()
  endif()
endif()


configure_file(src/config.h.in config.h)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

if(BUILD_DOCUMENTATION)
  set(DOXYGEN_GENERATE_HTML YES)
  set(DOXYGEN_GENERATE_XML YES)
  set(DOXYGEN_STRIP_FROM_PATH "include")
  set(DOXYGEN_MACRO_EXPANSION YES)
  set(DOXYGEN_PREDEFINED
    "ZONE_EXPORT=")
  # https://datatracker.ietf.org/doc/rfc<xxx>/
  # https://datatracker.ietf.org/doc/draft-ietf-<xxx>-<yyy>/
  # https://www.iana.org/assignments/<xxx>/<xxx>.xhtml#<yyy>
  # https://github.com/NLnetLabs/simdzone/issues/<xxx>
  set(DOXYGEN_ALIASES
    "rfc{1}=\"<a href='https://datatracker.ietf.org/doc/rfc\\1/'>[RFC\\1]</a>\""
    "draft{2}=\"<a href='https://datatracker.ietf.org/doc/draft-ietf-\\1-\\2/'>[draft-ietf-\\1-\\2]</a>\""
    "iana{3}=\"<a href='https://www.iana.org/assignments/\\2/\\2.xhtml#\\3'>\\1 registry</a>\""
    "issue{1}=\"<a href='https://github.com/NLnetLabs/simdzone/issues/\\1'>#\\1</a>\""
    "obsolete=<b>(OBSOLETE)</b>"
    "experimental=<b>(EXPERIMENTAL)</b>")
  set(DOXYGEN_VERBATIM_VARS DOXYGEN_ALIASES)
  find_package(Doxygen REQUIRED)
  doxygen_add_docs(doxygen include) # doxygen_add_docs is available since 3.9

  # Build target by issuing: cmake --build . --target manual
  find_package(Sphinx REQUIRED breathe)
  sphinx_add_docs(
    manual
    BREATHE_PROJECTS doxygen
    BUILDER html
    SOURCE_DIRECTORY doc/manual)
endif()

# Generate Package Configuration file
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/simdzoneConfig.cmake.in
  simdzoneConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simdzone)

# Generate Package Version file
write_basic_package_version_file(
  simdzoneConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/simdzoneConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/simdzoneConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simdzone)

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/zone.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/zone/attributes.h
        ${CMAKE_CURRENT_BINARY_DIR}/include/zone/export.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zone/)

install(
  EXPORT simdzone
  FILE simdzoneTargets.cmake
  NAMESPACE "simdzone::"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simdzone)

install(
  TARGETS zone
  EXPORT simdzone
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
