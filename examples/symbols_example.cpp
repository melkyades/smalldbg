// Example demonstrating symbol resolution
#include "smalldbg/Debugger.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Process.h"
#include <iostream>
#include <iomanip>

using namespace smalldbg;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable>\n";
        std::cerr << "Example: " << argv[0] << " test_target.exe\n";
        return 1;
    }

    std::string exePath = argv[1];
    
    // Create debugger and launch process
    Debugger dbg(Mode::External, Arch::X64);
    dbg.setLogCallback([](const std::string &m){ 
        std::cout << "[DBG] " << m << std::endl; 
    });
    
    std::cout << "Launching " << exePath << "...\n";
    if (dbg.launch(exePath, {}) != Status::Ok) {
        std::cerr << "Failed to launch\n";
        return 1;
    }
    
    // Wait for process creation
    auto reason = dbg.waitForEvent(StopReason::ProcessCreated);
    if (reason != StopReason::ProcessCreated) {
        std::cerr << "Failed to get ProcessCreated event\n";
        return 1;
    }
    
    std::cout << "Process launched successfully\n";
    auto pid = dbg.attachedPid();
    if (pid) {
        std::cout << "PID: " << *pid << "\n";
    }
    
    // Resume to initial breakpoint first
    std::cout << "\nWaiting for initial breakpoint...\n";
    dbg.resume();
    reason = dbg.waitForEvent(StopReason::InitialBreakpoint);
    
    if (reason != StopReason::InitialBreakpoint) {
        std::cerr << "Failed to get InitialBreakpoint event\n";
        dbg.detach();
        return 1;
    }
    
    std::cout << "Hit initial breakpoint\n";
    
    // Symbol provider is automatically initialized on process creation
    std::cout << "\nQuerying symbols...\n";
    auto* symbols = dbg.getSymbolProvider();
    
    // Get current stop address and query symbols
    Address addr = dbg.getStopAddress();
    std::cout << "\nStopped at address: 0x" << std::hex << addr << std::dec << "\n";
    
    // Try to get symbol at this address
    auto symbol = symbols->getSymbolByAddress(addr);
    if (symbol) {
        std::cout << "Symbol at address:\n";
        std::cout << "  Name: " << symbol->name << "\n";
        std::cout << "  Address: 0x" << std::hex << symbol->address << std::dec << "\n";
        std::cout << "  Size: " << symbol->size << " bytes\n";
        std::cout << "  Module: " << symbol->moduleName << "\n";
    } else {
        std::cout << "No symbol found at this address\n";
    }
    
    // Try to look up main function
    std::cout << "\nLooking up 'main' symbol...\n";
    auto mainSymbol = symbols->getSymbolByName("main");
    if (mainSymbol) {
        std::cout << "Found 'main' function:\n";
        std::cout << "  Name: " << mainSymbol->name << "\n";
        std::cout << "  Address: 0x" << std::hex << mainSymbol->address << std::dec << "\n";
        std::cout << "  Size: " << mainSymbol->size << " bytes\n";
        std::cout << "  Module: " << mainSymbol->moduleName << "\n";
    } else {
        std::cout << "'main' symbol not found\n";
    }
    
    // Try to get source location
    auto location = symbols->getSourceLocation(addr);
    if (location) {
        std::cout << "\nSource location:\n";
        std::cout << "  File: " << location->filename << "\n";
        std::cout << "  Line: " << location->line << "\n";
    } else {
        std::cout << "\nNo source information available\n";
    }
    
    // Cleanup
    std::cout << "\nDetaching...\n";
    dbg.detach();
    
    std::cout << "Done.\n";
    return 0;
}
