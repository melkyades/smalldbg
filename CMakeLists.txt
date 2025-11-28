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

add_executable(test_backend tests/test_stub.cpp)
target_link_libraries(test_backend PRIVATE smalldbg)

enable_testing()
add_test(NAME backend-test COMMAND test_backend)
