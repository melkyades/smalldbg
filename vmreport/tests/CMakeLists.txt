# Tests for the report library, run on snapshot targets and files only.
find_package(doctest REQUIRED)

add_executable(vmreport_tests test_report.cpp)
target_link_libraries(vmreport_tests PRIVATE vmreport doctest::doctest)

add_test(NAME vmreport-tests COMMAND vmreport_tests)
