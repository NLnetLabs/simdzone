cmake_minimum_required(VERSION 3.10)
project(zone LANGUAGES C VERSION 0.0.1 DESCRIPTION "Fast and standards compliant DNS zone file parser")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

add_subdirectory(compat)

# FIXME: scanner-types.h can be generated eventually
add_library(zone SHARED src/zone.c src/scanner.c src/parser.c src/log.c src/types.c src/types.h compat/b64_pton.c)
target_include_directories(
  zone PUBLIC include $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
set_target_properties(zone PROPERTIES C_STANDARD_REQUIRED 11)
target_link_libraries(zone b64_pton b64_ntop)

option(BUILD_TESTING "Build the testing tree." OFF)

include(CTest)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
