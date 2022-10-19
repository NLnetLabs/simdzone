cmake_minimum_required(VERSION 3.18)
project(simdzone LANGUAGES C VERSION 0.1.0)

add_executable(simdzone src/zone.c)
target_include_directories(
  simdzone PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_options(
  simdzone PRIVATE "-mavx2" "-mpclmul" "-mpopcnt" "-Wall" "-Wextra")
#target_compile_options(
#  simdzone PRIVATE "-msse4.1" "-mpclmul")
