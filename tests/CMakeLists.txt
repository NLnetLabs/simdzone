find_package(cmocka REQUIRED)
cmocka_add_tests(zone-tests scanner.c types.c wks.c svcb.c nsec.c base.c file.c)

target_link_libraries(zone-tests PRIVATE zone)
