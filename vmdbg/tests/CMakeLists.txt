# Unit tests for vmdbg: the Smalltalk object model, run on a memory the test
# builds, with no target and no debugger.
find_package(doctest REQUIRED)

add_executable(vmdbg_tests test_smalltalk_model.cpp)
target_link_libraries(vmdbg_tests PRIVATE vmdbg doctest::doctest)

add_test(NAME vmdbg-tests COMMAND vmdbg_tests)
