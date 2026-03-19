# Tests CMakeLists.txt

add_executable(test_backend test_harness.cpp)
target_link_libraries(test_backend PRIVATE smalldbg)

if(WIN32)
    add_executable(test_attach test_attach.cpp)
    target_link_libraries(test_attach PRIVATE smalldbg)
endif()

# A small instrumented program used by tests so we can exercise breakpoints, stepping and
# predictable behavior without relying on external system tools.
add_executable(test_target test_target.cpp)

# ensure test_target can see our internal src/platform headers
target_include_directories(test_target PRIVATE ${CMAKE_SOURCE_DIR}/src)

if(WIN32)
    target_sources(test_target PRIVATE ${CMAKE_SOURCE_DIR}/src/platform/windows/Platform.cpp)
else()
    target_sources(test_target PRIVATE ${CMAKE_SOURCE_DIR}/src/platform/posix/Platform.cpp)
endif()

enable_testing()
add_test(NAME backend-test COMMAND test_backend)

# Include DbgEng register tests (Windows only, separate diagnostic tools)
if(WIN32)
    add_subdirectory(dbgeng_regs)
endif()
