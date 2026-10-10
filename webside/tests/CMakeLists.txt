# Unit tests for the webside session/server layer.
find_package(doctest REQUIRED)

add_executable(webside_tests
    test_websidesession.cpp
    test_http_server.cpp
    test_inspector_json.cpp
    test_main.cpp
    test_smalltalk_session.cpp
    test_webside_server.cpp
)
target_include_directories(webside_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/vmdbg/tests)
target_link_libraries(webside_tests PRIVATE webside_common doctest::doctest)

# The live frame-API test drives a real target process.
add_dependencies(webside_tests test_target)
target_compile_definitions(webside_tests PRIVATE
    WEBSIDE_TEST_TARGET="$<TARGET_FILE:test_target>")

add_test(NAME webside-tests COMMAND webside_tests)
