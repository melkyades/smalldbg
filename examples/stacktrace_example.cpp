#include "smalldbg/Debugger.h"
#include "smalldbg/Thread.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackTrace.h"
#include <iostream>
#include <iomanip>

using namespace smalldbg;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable> [--download-symbols]\n";
        std::cerr << "  --download-symbols: Enable downloading symbols from Microsoft symbol server\n";
        return 1;
    }

    bool downloadSymbols = false;
    if (argc > 2 && std::string(argv[2]) == "--download-symbols") {
        downloadSymbols = true;
    }

    Debugger dbg(Mode::External);
    
    // Set symbol options early (before process creation)
    SymbolOptions symOpts;
    symOpts.cacheDirectory = "C:\\Symbols";      // Use C: drive for cache
    symOpts.useSymbolServer = downloadSymbols;    // Enable/disable symbol server
    // Use immediate loading when symbol server is disabled for better export table resolution
    symOpts.deferredLoading = downloadSymbols;    // Defer only when downloading from server
    symOpts.loadLineInfo = true;                  // Load source line information
    
    dbg.setSymbolOptions(symOpts);
    
    // Launch the target process
    std::cout << "Launching " << argv[1] << "...\n";
    Status status = dbg.launch(argv[1]);
    if (status != Status::Ok) {
        std::cerr << "Failed to launch process\n";
        return 1;
    }
    
    std::cout << "Process launched successfully\n";
    auto pid = dbg.attachedPid();
    if (pid) {
        std::cout << "PID: " << *pid << "\n";
    }
    
    // Wait for process created event
    StopReason reason = dbg.waitForEvent(StopReason::ProcessCreated);
    if (reason != StopReason::ProcessCreated) {
        std::cerr << "Failed to get ProcessCreated event\n";
        dbg.detach();
        return 1;
    }
    
    std::cout << "Process created\n";
    
    // Symbols are automatically initialized by the backend when process is created
    if (downloadSymbols) {
        std::cout << "\nSymbol server ENABLED - symbols will be downloaded to: " 
                  << symOpts.cacheDirectory << "\n";
        std::cout << "Note: First download may be slow!\n";
    } else {
        std::cout << "\nSymbol server DISABLED - using only local symbols\n";
    }
    
    // Resume to initial breakpoint
    dbg.resume();
    reason = dbg.waitForEvent(StopReason::InitialBreakpoint);
    if (reason != StopReason::InitialBreakpoint) {
        std::cerr << "Failed to get InitialBreakpoint event\n";
        dbg.detach();
        return 1;
    }
    
    std::cout << "Hit initial breakpoint\n";
    
    // Set a breakpoint on main
    auto* symbols = dbg.getSymbolProvider();
    auto mainSymbol = symbols->getSymbolByName("main");
    if (mainSymbol) {
        std::cout << "\nSetting breakpoint on main at 0x" << std::hex 
                  << mainSymbol->address << std::dec << "\n";
        status = dbg.setBreakpoint(mainSymbol->address, "main");
        if (status != Status::Ok) {
            std::cerr << "Warning: Failed to set breakpoint\n";
        }
        
        // Resume to main
        std::cout << "Resuming to main...\n";
        dbg.resume();
        reason = dbg.waitForEvent(StopReason::Breakpoint);
        if (reason != StopReason::Breakpoint) {
            std::cerr << "Did not hit breakpoint\n";
        } else {
            std::cout << "Hit breakpoint at main\n";
        }
    }
    
    // Get stack trace from current thread
    std::cout << "\n=== Stack Trace ===\n";
    
    auto currentThread = dbg.getCurrentThread();
    if (!currentThread) {
        std::cerr << "No current thread available\n";
    } else {
        StackTrace* stackTrace = currentThread->getStackTrace();
        if (!stackTrace) {
            std::cerr << "Failed to get stack trace\n";
        } else {
            const auto& frames = stackTrace->getFrames();
            std::cout << "Collected " << frames.size() << " frame(s)\n\n";
            
            for (size_t i = 0; i < frames.size(); i++) {
                const auto& frame = *frames[i];
                    
                std::cout << "#" << i << "  ";
                std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') 
                          << frame.ip() << std::dec << " in ";                    if (!frame.functionName.empty()) {
                        std::cout << frame.functionName;
                        if (frame.functionOffset > 0) {
                            std::cout << "+0x" << std::hex << frame.functionOffset << std::dec;
                        }
                    } else if (!frame.moduleName.empty()) {
                        // No function name but we have module - show module+offset
                        std::cout << frame.moduleName << "+0x" << std::hex << frame.functionOffset << std::dec;
                    } else {
                        std::cout << "??";
                    }
                    
                    if (!frame.moduleName.empty()) {
                        std::cout << " (" << frame.moduleName << ")";
                    }
                    
                    std::cout << "\n";
                    
                    if (!frame.sourceFile.empty() && frame.sourceLine > 0) {
                        std::cout << "    at " << frame.sourceFile << ":" << frame.sourceLine << "\n";
                    }
                    
                    // Show frame and stack pointers
                    std::cout << "    fp=0x" << std::hex << frame.fp() 
                              << " sp=0x" << frame.sp() << std::dec << "\n";
            }
            
            delete stackTrace;
        }
    }
    
    // Cleanup
    std::cout << "\nDetaching...\n";
    dbg.detach();
    
    std::cout << "Done.\n";
    return 0;
}
