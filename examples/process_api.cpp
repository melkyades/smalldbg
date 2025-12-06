// Example demonstrating the Process/Thread abstraction
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include <iostream>
#include <iomanip>

using namespace smalldbg;

void printRegisters(const Registers& regs) {
    if (regs.arch == Arch::X64) {
        std::cout << "  RAX: 0x" << std::hex << regs.x64.rax << "\n";
        std::cout << "  RBX: 0x" << std::hex << regs.x64.rbx << "\n";
        std::cout << "  RCX: 0x" << std::hex << regs.x64.rcx << "\n";
        std::cout << "  RDX: 0x" << std::hex << regs.x64.rdx << "\n";
        std::cout << "  RSP: 0x" << std::hex << regs.x64.rsp << "\n";
        std::cout << "  RBP: 0x" << std::hex << regs.x64.rbp << "\n";
        std::cout << "  RIP: 0x" << std::hex << regs.x64.rip << "\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>\n";
        std::cerr << "   or: " << argv[0] << " --launch <executable> [args...]\n";
        return 1;
    }

    Debugger dbg(Mode::External, Arch::X64);
    
    // Check if we should launch instead of attach
    if (std::string(argv[1]) == "--launch") {
        if (argc < 3) {
            std::cerr << "Error: --launch requires an executable path\n";
            return 1;
        }
        
        std::vector<std::string> args;
        for (int i = 3; i < argc; i++) {
            args.push_back(argv[i]);
        }
        
        std::cout << "Launching " << argv[2] << "...\n";
        if (dbg.launch(argv[2], args) != Status::Ok) {
            std::cerr << "Failed to launch\n";
            return 1;
        }
        
        // Wait for process created event
        if (dbg.waitForEvent(StopReason::ProcessCreated) != StopReason::ProcessCreated) {
            std::cerr << "Failed to get ProcessCreated event\n";
            return 1;
        }
        
        std::cout << "Process launched successfully\n";
        
        // Continue to initial breakpoint
        dbg.resume();
        if (dbg.waitForEvent(StopReason::InitialBreakpoint) != StopReason::InitialBreakpoint) {
            std::cerr << "Failed to hit initial breakpoint\n";
            return 1;
        }
    } else {
        int pid = std::atoi(argv[1]);
        
        std::cout << "Attaching to PID " << pid << "...\n";
        if (dbg.attach(pid) != Status::Ok) {
            std::cerr << "Failed to attach\n";
            return 1;
        }
        
        std::cout << "Attached successfully\n";
    }
    
    // Get the Process abstraction
    auto process = dbg.getProcess();
    if (!process) {
        std::cerr << "No process object available\n";
        return 1;
    }
    
    std::cout << "Process PID: " << process->getPid() << "\n";
    std::cout << "Process attached: " << (process->isAttached() ? "yes" : "no") << "\n";
    
    // Suspend the process to inspect it
    std::cout << "\nSuspending process...\n";
    if (dbg.suspend() != Status::Ok) {
        std::cerr << "Failed to suspend\n";
        return 1;
    }
    
    // Wait for the process to stop
    dbg.waitForEvent(StopReason::None, 1000);
    
    if (!process->isStopped()) {
        std::cerr << "Process didn't stop\n";
        return 1;
    }
    
    std::cout << "Process stopped at: 0x" << std::hex << process->getStopAddress() << "\n";
    
    // Get the current thread from debugger
    auto thread = dbg.getCurrentThread();
    if (!thread) {
        std::cerr << "No current thread\n";
        return 1;
    }
    
    std::cout << "\nCurrent thread ID: " << thread->getThreadId() << "\n";
    std::cout << "Thread IP: 0x" << std::hex << thread->getInstructionPointer() << "\n";
    std::cout << "Thread SP: 0x" << std::hex << thread->getStackPointer() << "\n";
    std::cout << "Thread FP: 0x" << std::hex << thread->getFramePointer() << "\n";
    
    // Get registers via thread
    Registers regs{};
    if (thread->getRegisters(regs) == Status::Ok) {
        std::cout << "\nRegisters:\n";
        printRegisters(regs);
    }
    
    // Read some memory via process
    uint64_t stackValue = 0;
    Address sp = thread->getStackPointer();
    if (process->readMemory(sp, &stackValue, sizeof(stackValue)) == Status::Ok) {
        std::cout << "\nValue at stack pointer: 0x" << std::hex << stackValue << "\n";
    }
    
    // Enumerate threads
    std::cout << "\nThreads in process:\n";
    auto threads = process->threads();
    for (const auto& t : threads) {
        std::cout << "  Thread " << t->getThreadId() 
                  << " @ IP=0x" << std::hex << t->getInstructionPointer() << "\n";
    }
    
    // Resume and detach
    std::cout << "\nResuming process...\n";
    dbg.resume();
    
    std::cout << "Detaching...\n";
    dbg.detach();
    
    std::cout << "Done.\n";
    return 0;
}
