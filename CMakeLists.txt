cmake_minimum_required(VERSION 3.10)
project(smalldbg VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(smalldbg STATIC
    src/Debugger.cpp
    src/backends/WindowsBackend.cpp
    src/bindings/CAPI.cpp
)

target_include_directories(smalldbg PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_executable(example src/main_example.cpp)
target_link_libraries(example PRIVATE smalldbg)

add_executable(test_backend tests/test_harness.cpp)
target_link_libraries(test_backend PRIVATE smalldbg)

# A small instrumented program used by tests so we can exercise breakpoints, stepping and
# predictable behavior without relying on external system tools.
add_executable(test_target tests/test_target.cpp)

# ensure test_target can see our internal src/platform headers
target_include_directories(test_target PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WIN32)
    target_sources(test_target PRIVATE src/platform/windows/Platform.cpp)
else()
    target_sources(test_target PRIVATE src/platform/posix/Platform.cpp)
endif()

enable_testing()
add_test(NAME backend-test COMMAND test_backend)
