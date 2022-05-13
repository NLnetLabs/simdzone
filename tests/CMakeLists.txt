find_package(cmocka REQUIRED)
cmocka_add_tests(zone-tests scanner.c)

target_link_libraries(zone-tests PRIVATE zone)
