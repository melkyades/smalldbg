# Unit tests for vmdbg, with no target to debug: the inspectors, and the
# Smalltalk object model on a heap the test lays out as a snapshot.
find_package(doctest REQUIRED)

add_executable(vmdbg_tests
    test_smalltalk_model.cpp
    test_vm_inspector.cpp
)
target_link_libraries(vmdbg_tests PRIVATE vmdbg doctest::doctest)

add_test(NAME vmdbg-tests COMMAND vmdbg_tests)
