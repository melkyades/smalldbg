// DbgEng register-reading test target (x86 version).
//
// This links with test_regs_x86.S which contains assembly functions that
// place KNOWN values in registers and hit int3.  The companion harness
// catches each breakpoint and verifies register values.

#include <windows.h>
#include <cstdio>
#include <cstdint>

// Assembly functions from test_regs_x86.asm
extern "C" {
    void test_regs_small(void);
    void test_regs_large32(void);
    void test_regs_deadbeef(void);
}

struct TestPoint {
    const char* name;
    void (*func)(void);
    uint32_t eax, ebx, ecx, edx, esi, edi;
};

static const TestPoint testPoints[] = {
    { "small",
      test_regs_small,
      0x00000001, 0x00000002, 0x00000003,
      0x00000004, 0x00000005, 0x00000006 },

    { "large32",
      test_regs_large32,
      0xAABBCCDD, 0x11223344, 0x55667788,
      0x99AABBCC, 0xDDEEFF00, 0x12345678 },

    { "deadbeef",
      test_regs_deadbeef,
      0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF,
      0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF },
};

int main() {
    const int numTests = sizeof(testPoints) / sizeof(testPoints[0]);

    // Print header so harness can parse
    printf("DBGENG_REG_TEST_TARGET_X86\n");
    printf("NUM_TESTS=%d\n", numTests);
    fflush(stdout);

    // Print expected values for each test point
    for (int i = 0; i < numTests; ++i) {
        const auto& tp = testPoints[i];
        printf("TEST[%d]=%s eax=0x%08X ebx=0x%08X ecx=0x%08X "
               "edx=0x%08X esi=0x%08X edi=0x%08X\n",
               i, tp.name,
               tp.eax, tp.ebx, tp.ecx, tp.edx, tp.esi, tp.edi);
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
