cmake_minimum_required(VERSION 3.18)
project(simdzone LANGUAGES C VERSION 0.1.0)

add_executable(dfa-table src/dfa-table.c)

add_custom_command(
  OUTPUT transitions.h
  COMMAND dfa-table
  ARGS transitions.h
  DEPENDS src/dfa.h dfa-table)

add_executable(simdzone src/zone.c transitions.h)
target_include_directories(
  simdzone
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
target_compile_options(
  simdzone PRIVATE "-mavx2" "-mpclmul" "-mpopcnt" "-Wall" "-Wextra")
