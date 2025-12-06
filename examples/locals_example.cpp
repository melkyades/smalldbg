// Example: Inspect local variables using register unwinding
#define NOMINMAX  // Prevent windows.h from defining min/max macros
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackTrace.h"
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>

using namespace smalldbg;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_executable>\n";
        return 1;
    }
    
    std::string targetPath = argv[1];
    
    // Create debugger
    Debugger debugger(Mode::External, Arch::X64);
    
    // Enable symbol server
    SymbolOptions symOpts;
    symOpts.useSymbolServer = false;  // Disable for faster startup
    symOpts.loadLineInfo = true;
    debugger.setSymbolOptions(symOpts);
    
    // Launch target
    std::cout << "Launching " << targetPath << "...\n";
    if (debugger.launch(targetPath) != Status::Ok) {
        std::cerr << "Failed to launch process\n";
        return 1;
    }
    
    std::cout << "Process launched successfully\n";
    std::cout << "PID: " << debugger.attachedPid().value_or(0) << "\n";
    
    // Wait for initial breakpoint
    auto reason = debugger.waitForEvent(StopReason::ProcessCreated, 5000);
    if (reason != StopReason::ProcessCreated && reason != StopReason::InitialBreakpoint) {
        std::cerr << "Failed to receive process creation event\n";
        debugger.detach();
        return 1;
    }
    
    std::cout << "Process created\n";
    
    auto symbols = debugger.getSymbolProvider();
    std::cout << "\nSymbol server " << (symOpts.useSymbolServer ? "ENABLED" : "DISABLED") 
              << " - using only local symbols\n";
    
    // Resume to initial breakpoint if needed
    if (reason == StopReason::ProcessCreated) {
        debugger.resume();
        reason = debugger.waitForEvent(StopReason::InitialBreakpoint, 5000);
        if (reason != StopReason::InitialBreakpoint) {
            std::cerr << "Failed to hit initial breakpoint\n";
            debugger.detach();
            return 1;
        }
        std::cout << "Hit initial breakpoint\n";
    }
    
    // Find main symbol
    auto mainSym = symbols->getSymbolByName("main");
    if (!mainSym) {
        std::cerr << "Could not find 'main' symbol\n";
        debugger.detach();
        return 1;
    }
    
    std::cout << "\nSetting breakpoint on main at 0x" << std::hex << mainSym->address << std::dec << "\n";
    debugger.setBreakpoint(mainSym->address, "main");
    
    // Resume to main
    std::cout << "Resuming to main...\n";
    debugger.resume();
    reason = debugger.waitForEvent(StopReason::Breakpoint, 5000);
    
    if (reason != StopReason::Breakpoint) {
        std::cerr << "Failed to hit breakpoint at main\n";
        debugger.detach();
        return 1;
    }
    
    std::cout << "Hit breakpoint at main\n";
    
    // Get current thread and create stack trace
    auto thread = debugger.getCurrentThread();
    if (!thread) {
        std::cerr << "Failed to get current thread\n";
        debugger.detach();
        return 1;
    }
    
    StackTrace stackTrace(thread.get());
    if (stackTrace.unwind() != Status::Ok) {
        std::cerr << "Failed to unwind stack\n";
        debugger.detach();
        return 1;
    }
    
    const auto& frames = stackTrace.getFrames();
    std::cout << "\n=== Stack Trace with Local Variables ===\n";
    std::cout << "Collected " << frames.size() << " frame(s)\n\n";
    
    for (size_t i = 0; i < frames.size(); ++i) {
        const auto& frame = *frames[i];
        
        // Print the frame (handles function name, source location, and basic local variables)
        frame.print(std::cout, i);
        
        // Special handling for argv (char**) to show array contents
        for (const auto& var : frame.localVariables) {
            if (var.name == "argv" && var.size == 8) {
                auto value = var.getValue();
                if (value) {
                    std::cout << "      argv contents:";
                    
                    // Read the char** array
                    uint64_t argvPtr = *value;
                    for (int j = 0; j < 10; j++) {  // Read up to 10 args
                        // Read argv[j] (a char* pointer)
                        uint64_t strPtr = 0;
                        auto readResult = debugger.readMemory(argvPtr + j * 8, &strPtr, 8);
                        if (readResult != Status::Ok || strPtr == 0) {
                            break;  // NULL terminator or read failed
                        }
                        
                        // Read the string at argv[j]
                        char buffer[256] = {};
                        readResult = debugger.readMemory(strPtr, buffer, sizeof(buffer) - 1);
                        if (readResult == Status::Ok) {
                            std::cout << "\n        [" << j << "] = \"" << buffer << "\"";
                        }
                    }
                    std::cout << "\n";
                }
            }
        }
        
        std::cout << "\n";
    }
    
    std::cout << "Detaching...\n";
    debugger.detach();
    std::cout << "Done.\n";
    
    return 0;
}
