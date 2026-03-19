# DbgEng Register Reading Tests
#
# Tests that verify DbgEng register-reading APIs work correctly.
# Requires same-architecture build (x86 debugger for x86 target, etc.)

# Enable MASM assembler - CMake finds the right ml/ml64 based on target arch
enable_language(ASM_MASM)

# Select architecture-appropriate sources
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TEST_REGS_ARCH "x64")
    set(TEST_REGS_ASM ${CMAKE_CURRENT_SOURCE_DIR}/test_regs_x64.asm)
    set(TEST_REGS_CPP ${CMAKE_CURRENT_SOURCE_DIR}/test_dbgeng_target_x64.cpp)
else()
    set(TEST_REGS_ARCH "x86")
    set(TEST_REGS_ASM ${CMAKE_CURRENT_SOURCE_DIR}/test_regs_x86.asm)
    set(TEST_REGS_CPP ${CMAKE_CURRENT_SOURCE_DIR}/test_dbgeng_target_x86.cpp)
endif()

message(STATUS "Building test_dbgeng_target for ${TEST_REGS_ARCH}")

# Test target - places known values in registers and hits int3
add_executable(test_dbgeng_target
    ${TEST_REGS_CPP}
    ${TEST_REGS_ASM}
)

# Disable SAFESEH for x86 (our test asm has no exception handlers)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_options(test_dbgeng_target PRIVATE /SAFESEH:NO)
endif()

# Test harness - launches target and verifies register values via DbgEng
add_executable(test_dbgeng_regs test_dbgeng_regs.cpp)
target_link_libraries(test_dbgeng_regs PRIVATE dbgeng)
