#include "smalldbg/Debugger.h"
#include <iostream>

int main() {
    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
    dbg.setLogCallback([](const std::string &m){ std::cout << "[LOG] " << m << std::endl; });

    if (dbg.launch("C:\\Windows\\System32\\cmd.exe", {"/C","echo","hello"}) != smalldbg::Status::Ok) {
        std::cerr << "launch failed\n";
        return 2;
    }

    // Wait for ProcessCreated event
    auto reason = dbg.waitForEvent(smalldbg::StopReason::ProcessCreated);
    if (reason != smalldbg::StopReason::ProcessCreated) {
        std::cerr << "Error: Expected ProcessCreated event\n";
        return 3;
    }
    std::cout << "Process created successfully" << std::endl;

    auto pid = dbg.attachedPid();
    std::cout << "attached pid: " << (pid ? std::to_string(*pid) : std::string("-")) << std::endl;

    // set a breakpoint
    dbg.setBreakpoint(0x401000, "entry");

    auto bps = dbg.listBreakpoints();
    std::cout << "breakpoints: " << bps.size() << std::endl;

    // Resume from process creation and wait for initial breakpoint
    dbg.resume();
    reason = dbg.waitForEvent(smalldbg::StopReason::InitialBreakpoint);
    if (reason == smalldbg::StopReason::InitialBreakpoint) {
        std::cout << "Hit initial breakpoint" << std::endl;
    }

    dbg.step();
    // simple memory test
    uint32_t x = 42;
    if (dbg.writeMemory(0x100, &x, sizeof(x)) == smalldbg::Status::Ok) {
        uint32_t y = 0;
        dbg.readMemory(0x100, &y, sizeof(y));
        std::cout << "mem[0x100] = " << y << std::endl;
    }
    dbg.resume();
    dbg.detach();

    return 0;
}
