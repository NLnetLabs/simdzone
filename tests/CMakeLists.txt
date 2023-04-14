find_package(cmocka REQUIRED)
cmocka_add_tests(zone-tests types.c include.c)

target_link_libraries(zone-tests PRIVATE zone)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes -Wno-deprecated-declarations)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(zone-tests PRIVATE -Wno-missing-prototypes)
endif()
