# Unit tests for the webside session/server layer.
find_package(doctest REQUIRED)

add_executable(webside_tests
    test_websidesession.cpp
)
target_include_directories(webside_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(webside_tests PRIVATE doctest::doctest)

add_test(NAME webside-tests COMMAND webside_tests)
