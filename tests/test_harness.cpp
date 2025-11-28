#include "smalldbg/Debugger.h"
#include <iostream>
#include <thread>
#include <chrono>

#define TEST_ASSERT(cond, msg, code) do { \
    if (!(cond)) { \
        std::cerr << "TEST FAILED: " << msg << std::endl; \
        return code; \
    } \
} while(0)

#define TEST_PASS(msg) std::cout << "[PASS] " << msg << std::endl

int test_launch_and_attach(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 1: Launch Process ===" << std::endl;
#if defined(_WIN32)
    auto s = dbg.launch("test_target.exe", {"wait"});
#else
    auto s = dbg.launch("./test_target", {"wait"});
#endif
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to launch test_target", 2);
    TEST_PASS("Process launched successfully");
    
    // allow the debug loop to start for a short while
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    std::cout << "\n=== Test 2: Verify Attached State ===" << std::endl;
    TEST_ASSERT(dbg.isAttached(), "Debugger should be attached", 3);
    TEST_PASS("Debugger is attached");
    
    auto pid = dbg.attachedPid();
    TEST_ASSERT(pid.has_value(), "Should have attached PID", 4);
    std::cout << "[INFO] Attached to PID: " << pid.value() << std::endl;
    TEST_PASS("PID retrieval successful");
    
    return 0;
}

int test_register_access(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 3: Register Access ===" << std::endl;
    smalldbg::Registers r;
    auto s = dbg.getRegisters(r);
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to get registers", 5);
    TEST_ASSERT(r.arch == smalldbg::Arch::X64, "Architecture mismatch", 6);
    std::cout << "[INFO] RIP/PC: 0x" << std::hex << r.x64.rip << std::dec << std::endl;
    TEST_PASS("Register access successful");
    
    return 0;
}

int test_breakpoint_management(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 4: Breakpoint Management ===" << std::endl;
    auto bps = dbg.listBreakpoints();
    size_t initialBpCount = bps.size();
    std::cout << "[INFO] Initial breakpoint count: " << initialBpCount << std::endl;
    
    // Try to set a breakpoint at the current instruction pointer
    smalldbg::Registers rForBp;
    if (dbg.getRegisters(rForBp) == smalldbg::Status::Ok) {
        smalldbg::Address testAddr = rForBp.x64.rip;
        auto s = dbg.setBreakpoint(testAddr, "test_bp");
        if (s == smalldbg::Status::Ok) {
            TEST_PASS("Breakpoint set successfully");
            
            bps = dbg.listBreakpoints();
            TEST_ASSERT(bps.size() == initialBpCount + 1, "Breakpoint count should increase", 8);
            
            bool foundBp = false;
            for (const auto& bp : bps) {
                if (bp.addr == testAddr && bp.name == "test_bp") {
                    foundBp = true;
                    break;
                }
            }
            TEST_ASSERT(foundBp, "Should find the breakpoint we set", 9);
            TEST_PASS("Breakpoint listed correctly");
            
            // Clear the breakpoint
            s = dbg.clearBreakpoint(testAddr);
            TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to clear breakpoint", 10);
            TEST_PASS("Breakpoint cleared successfully");
            
            bps = dbg.listBreakpoints();
            TEST_ASSERT(bps.size() == initialBpCount, "Breakpoint count should return to initial", 11);
            TEST_PASS("Breakpoint management verified");
        } else {
            std::cout << "[INFO] Breakpoint setting not supported/failed (OK for some backends)" << std::endl;
        }
    } else {
        std::cout << "[INFO] Cannot test breakpoints - register read failed" << std::endl;
    }
    
    return 0;
}

int test_run_control(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 5: Run Control (Resume/Step) ===" << std::endl;
    auto s = dbg.resume();
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to resume", 12);
    TEST_PASS("Resume successful");
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    s = dbg.step();
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to step", 13);
    TEST_PASS("Step successful");
    
    return 0;
}

int test_memory_operations(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 6: Memory Operations ===" << std::endl;
    smalldbg::Registers r;
    if (dbg.getRegisters(r) == smalldbg::Status::Ok) {
        uint64_t stackAddr = r.x64.rsp;
        uint8_t buffer[16] = {0};
        auto s = dbg.readMemory(stackAddr, buffer, sizeof(buffer));
        TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to read memory", 14);
        std::cout << "[INFO] Read " << sizeof(buffer) << " bytes from stack" << std::endl;
        TEST_PASS("Memory read successful");
        
        // Try to write to a writable region
        uint8_t testData[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        s = dbg.writeMemory(stackAddr, testData, sizeof(testData));
        if (s == smalldbg::Status::Ok) {
            TEST_PASS("Memory write successful");
        } else {
            std::cout << "[INFO] Memory write failed (expected on protected pages)" << std::endl;
        }
    }
    
    return 0;
}

int test_logging(int logCount) {
    std::cout << "\n=== Test 7: Logging Callback ===" << std::endl;
    TEST_ASSERT(logCount > 0, "Should have received log messages", 15);
    std::cout << "[INFO] Total log messages received: " << logCount << std::endl;
    TEST_PASS("Logging callback functional");
    
    return 0;
}

int test_detach(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 8: Detach ===" << std::endl;
    auto s = dbg.detach();
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to detach", 16);
    TEST_PASS("Detached successfully");
    
    TEST_ASSERT(!dbg.isAttached(), "Should not be attached after detach", 17);
    TEST_PASS("Verified detached state");
    
    return 0;
}

int main() {
    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
    int logCount = 0;
    
    dbg.setLogCallback([&logCount](const std::string &m){
        std::cout << "[TEST LOG] " << m << std::endl;
        logCount++;
    });

    int result = 0;
    
    // Run all tests in sequence
    if ((result = test_launch_and_attach(dbg)) != 0) return result;
    if ((result = test_register_access(dbg)) != 0) return result;
    if ((result = test_breakpoint_management(dbg)) != 0) return result;
    if ((result = test_run_control(dbg)) != 0) return result;
    if ((result = test_memory_operations(dbg)) != 0) return result;
    if ((result = test_logging(logCount)) != 0) return result;
    if ((result = test_detach(dbg)) != 0) return result;

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    return 0;
}
