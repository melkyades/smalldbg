#include "smalldbg/Debugger.h"
#include <iostream>
#include <windows.h>
#include <thread>
#include <chrono>

int main() {
    // Launch a target process that we'll attach to
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessA(nullptr, (char*)"test_target.exe wait", nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to create target process\n";
        return 1;
    }
    
    DWORD targetPid = pi.dwProcessId;
    std::cout << "Created target process with PID: " << targetPid << std::endl;
    
    // Give it a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Now try to attach
    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
    dbg.setLogCallback([](const std::string &m){ std::cout << "[LOG] " << m << std::endl; });
    
    auto status = dbg.attach(targetPid);
    if (status != smalldbg::Status::Ok) {
        std::cerr << "Failed to attach\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 2;
    }
    
    std::cout << "Attached successfully" << std::endl;
    
    // Try to get registers
    smalldbg::Registers r;
    if (dbg.getRegisters(r) == smalldbg::Status::Ok) {
        std::cout << "Got registers, RIP: 0x" << std::hex << r.x64.rip << std::dec << std::endl;
    }
    
    // Resume the process
    dbg.resume();
    std::cout << "Resumed process" << std::endl;
    
    // Wait a bit then detach
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    dbg.detach();
    std::cout << "Detached" << std::endl;
    
    // Cleanup
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    std::cout << "Test completed successfully" << std::endl;
    return 0;
}
