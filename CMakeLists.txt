cmake_minimum_required(VERSION 3.18)
project(
  simdzone
  LANGUAGES C
  VERSION 0.1.0
  DESCRIPTION "Fast and standards compliant DNS zone file parser")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

include(CheckIncludeFile)
include(CheckCCompilerFlag)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -pedantic -fjump-tables)
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
    if(WERROR)
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

add_library(simdzone STATIC src/zone.c src/types.c)

target_include_directories(
  simdzone PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
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

add_executable(parser src/main.c)
target_link_libraries(parser PRIVATE simdzone)

#option(BUILD_TESTING "Build the testing tree." OFF)
#
#include(CTest)
#
#if(BUILD_TESTING)
#  add_subdirectory(tests)
#endif()
