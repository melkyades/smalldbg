#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable> [args...]\\n";
        return 1;
    }

    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
    dbg.setLogCallback([](const std::string &m){ std::cout << "[LOG] " << m << std::endl; });

    std::vector<std::string> args;
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }

    if (dbg.launch(argv[1], args) != smalldbg::Status::Ok) {
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

    // Get process abstraction
    auto process = dbg.getProcess();
    if (process) {
        std::cout << "Process PID: " << process->getPid() << std::endl;
    }

    // set a breakpoint
    dbg.setBreakpoint(0x401000, "entry");

    auto bps = dbg.listBreakpoints();
    std::cout << "breakpoints: " << bps.size() << std::endl;

    // Resume from process creation and wait for initial breakpoint
    dbg.resume();
    reason = dbg.waitForEvent(smalldbg::StopReason::InitialBreakpoint);
    if (reason == smalldbg::StopReason::InitialBreakpoint) {
        std::cout << "Hit initial breakpoint" << std::endl;
        
        // Get current thread
        auto thread = dbg.getCurrentThread();
        if (thread) {
            std::cout << "Current thread ID: " << thread->getThreadId() << std::endl;
        }
    }

    // Step using current thread
    auto thread = dbg.getCurrentThread();
    if (thread) {
        dbg.step();
    }
    
    // simple memory test using process abstraction
    if (process) {
        uint32_t x = 42;
        if (process->writeMemory(0x100, &x, sizeof(x)) == smalldbg::Status::Ok) {
            uint32_t y = 0;
            process->readMemory(0x100, &y, sizeof(y));
            std::cout << "mem[0x100] = " << y << std::endl;
        }
    }
    
    dbg.resume();
    dbg.detach();

    return 0;
}
