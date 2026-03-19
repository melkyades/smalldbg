// DbgEng register-reading test target (x64 version).
//
// This links with test_regs_x64.S which contains assembly functions that
// place KNOWN values in registers and hit int3.  The companion harness
// (test_dbgeng_regs.exe) catches each breakpoint and verifies register values.

#include <windows.h>
#include <cstdio>
#include <cstdint>

// Assembly functions from test_regs_x64.S
extern "C" {
    void test_regs_small(void);
    void test_regs_large32(void);
    void test_regs_large64(void);
    void test_regs_deadbeef(void);
}

struct TestPoint {
    const char* name;
    void (*func)(void);
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, r8, r9;
};

static const TestPoint testPoints[] = {
    { "small",
      test_regs_small,
      0x0000000000000001, 0x0000000000000002, 0x0000000000000003,
      0x0000000000000004, 0x0000000000000005, 0x0000000000000006,
      0x0000000000000007, 0x0000000000000008 },

    { "large32",
      test_regs_large32,
      0x00000000AABBCCDD, 0x0000000011223344, 0x0000000055667788,
      0x0000000099AABBCC, 0x00000000DDEEFF00, 0x0000000012345678,
      0x00000000CAFEBABE, 0x00000000FEEDFACE },

    { "large64",
      test_regs_large64,
      0x123456789ABCDEF0, 0xFEDCBA9876543210, 0xAAAABBBBCCCCDDDD,
      0x1111222233334444, 0x5555666677778888, 0x9999AAAABBBBCCCC,
      0xDDDDEEEEFFFF0000, 0x0001000200030004 },

    { "deadbeef",
      test_regs_deadbeef,
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF },
};

int main() {
    const int numTests = sizeof(testPoints) / sizeof(testPoints[0]);

    // Print header so harness can parse
    printf("DBGENG_REG_TEST_TARGET_X64\n");
    printf("NUM_TESTS=%d\n", numTests);
    fflush(stdout);

    // Print expected values for each test point
    for (int i = 0; i < numTests; ++i) {
        const auto& tp = testPoints[i];
        printf("TEST[%d]=%s rax=0x%016llX rbx=0x%016llX rcx=0x%016llX "
               "rdx=0x%016llX rsi=0x%016llX rdi=0x%016llX r8=0x%016llX r9=0x%016llX\n",
               i, tp.name,
               (unsigned long long)tp.rax, (unsigned long long)tp.rbx,
               (unsigned long long)tp.rcx, (unsigned long long)tp.rdx,
               (unsigned long long)tp.rsi, (unsigned long long)tp.rdi,
               (unsigned long long)tp.r8,  (unsigned long long)tp.r9);
    }
    fflush(stdout);

    // Run each test point
    for (int i = 0; i < numTests; ++i) {
        printf("RUNNING_TEST[%d]=%s\n", i, testPoints[i].name);
        fflush(stdout);

        // Call the assembly function — it will int3 inside
        testPoints[i].func();

        printf("RESUMED_TEST[%d]=%s\n", i, testPoints[i].name);
        fflush(stdout);
    }

    printf("ALL_TESTS_DONE\n");
    fflush(stdout);

    return 0;
}
