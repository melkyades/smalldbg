#include <doctest/doctest.h>

#include "platform/windows/WoW64SyscallUnwinder.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Snapshot.h"
#include "smalldbg/StackTrace.h"

#include <vector>

using namespace smalldbg;

TEST_CASE("a syscall address is claimed only for a 32-bit target read by a "
          "64-bit debugger") {
    WoW64SyscallUnwinder unwinder;

    Registers x86;
    x86.arch = X86::instance();
    CHECK(unwinder.canUnwind(0x730002, x86, nullptr) == (sizeof(void*) == 8));
    CHECK_FALSE(unwinder.canUnwind(0x730010, x86, nullptr));
    CHECK_FALSE(unwinder.canUnwind(0x10000002, x86, nullptr));

    Registers x64;
    x64.arch = X64::instance();
    CHECK_FALSE(unwinder.canUnwind(0x730002, x64, nullptr));
}

TEST_CASE("a syscall frame returns to the address on top of the stack") {
    // The stack holds one return address, 0x401234.
    Debugger debugger(Mode::External, X86::instance(), Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({SnapshotRegion::fromBytes(
                0x2000, std::vector<uint8_t>{0x34, 0x12, 0x40, 0x00})})
            == Status::Ok);
    WoW64SyscallUnwinder unwinder;

    StackFrame frame;
    frame.registers.arch = X86::instance();
    frame.registers.x86.eip = 0x730002;
    frame.registers.x86.esp = 0x2000;

    unwinder.process(frame, &debugger);
    CHECK(frame.moduleName == "WoW64");
    CHECK(frame.functionName == "syscall");

    REQUIRE(unwinder.unwind(frame, &debugger) == Status::Ok);
    CHECK(frame.registers.x86.eip == 0x401234);
    CHECK(frame.registers.x86.esp == 0x2004);

    frame.registers.x86.esp = 0x3000;
    CHECK(unwinder.unwind(frame, &debugger) == Status::Error);
}
