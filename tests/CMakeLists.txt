find_package(cmocka REQUIRED)
cmocka_add_tests(zone-tests types.c include.c ip4.c time.c base32.c svcb.c syntax.c eui.c bounds.c)

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
target_sources(zone-tests PRIVATE "${xbounds_c}")
add_dependencies(zone-tests generate_xbounds_c)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes -Wno-deprecated-declarations)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes)
endif()
