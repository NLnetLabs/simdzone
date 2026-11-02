find_package(cmocka REQUIRED)

if(HAVE_WESTMERE)
  set(sources ${sources} westmere/bits.c)
  set_source_files_properties(westmere/bits.c PROPERTIES COMPILE_FLAGS "-march=westmere")
endif()
if(HAVE_HASWELL)
  set(sources ${sources} haswell/bits.c)
  set_source_files_properties(haswell/bits.c PROPERTIES COMPILE_FLAGS "-march=haswell")
endif()

cmocka_add_tests(zone-tests types.c include.c ip4.c time.c base32.c svcb.c syntax.c semantics.c eui.c bounds.c bits.c ttl.c fromcb.c)

set(xbounds ${CMAKE_CURRENT_SOURCE_DIR}/zones/xbounds.zone)
set(xbounds_c "${CMAKE_CURRENT_BINARY_DIR}/xbounds.c")
set(xxd_cmake ${CMAKE_CURRENT_SOURCE_DIR}/xxd.cmake)

add_custom_command(
  OUTPUT "${xbounds_c}"
  COMMAND ${CMAKE_COMMAND}
  ARGS "-DINPUT_FILE=${xbounds}" "-DOUTPUT_FILE=${xbounds_c}" -P ${xxd_cmake}
  DEPENDS "${xbounds}" "${xxd_cmake}")

add_custom_target(generate_xbounds_c DEPENDS "${xbounds_c}")

target_link_libraries(zone-tests PRIVATE zone)
target_sources(zone-tests PRIVATE "${xbounds_c}" tools.c fallback/bits.c ${sources})
add_dependencies(zone-tests generate_xbounds_c)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes -Wno-deprecated-declarations)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes)
endif()
