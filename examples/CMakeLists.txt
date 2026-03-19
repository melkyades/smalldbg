# Example programs demonstrating smalldbg usage

add_executable(example debugger_api.cpp)
target_link_libraries(example PRIVATE smalldbg)

add_executable(process_api process_api.cpp)
target_link_libraries(process_api PRIVATE smalldbg)

add_executable(symbols_example symbols_example.cpp)
target_link_libraries(symbols_example PRIVATE smalldbg)

add_executable(stacktrace_example stacktrace_example.cpp)
target_link_libraries(stacktrace_example PRIVATE smalldbg)

if(WIN32)
    add_executable(locals_example locals_example.cpp)
    target_link_libraries(locals_example PRIVATE smalldbg)

    # TTD (Time Travel Debugging) replay example
    add_executable(ttd_replay ttd_replay.cpp)
    target_link_libraries(ttd_replay PRIVATE smalldbg)
endif()
