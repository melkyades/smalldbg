# Unit tests for vmdbg, with no target to debug. What reads a heap or a stack
# reads one the test lays out as a snapshot.
find_package(doctest REQUIRED)

add_executable(vmdbg_tests
    test_smalltalk_model.cpp
    test_vm_inspector.cpp
    test_smalltalk_inspector.cpp
    test_address_table.cpp
    test_method_parser.cpp
    test_syntax_tree.cpp
    test_frame_unwinder.cpp
    test_target_spec.cpp
    test_tracer.cpp
    test_retainers.cpp
    test_json.cpp
    test_setup.cpp
)
target_link_libraries(vmdbg_tests PRIVATE vmdbg doctest::doctest)

add_test(NAME vmdbg-tests COMMAND vmdbg_tests)
