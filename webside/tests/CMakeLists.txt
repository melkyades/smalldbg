# Unit tests for the webside session/server layer.
find_package(doctest REQUIRED)

add_executable(webside_tests
    test_websidesession.cpp
    test_http_server.cpp
    test_main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/HttpServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/WebsideSession.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Workspace.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Json.cpp
)
target_include_directories(webside_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(webside_tests PRIVATE vmdbg httplib::httplib doctest::doctest)

# The live frame-API test drives a real target process.
add_dependencies(webside_tests test_target)
target_compile_definitions(webside_tests PRIVATE
    WEBSIDE_TEST_TARGET="$<TARGET_FILE:test_target>")

add_test(NAME webside-tests COMMAND webside_tests)
