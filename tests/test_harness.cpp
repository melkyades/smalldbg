#include "smalldbg/Debugger.h"
#include "smalldbg/StackTrace.h"
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
    
    // Wait for ProcessCreated event
    auto reason = dbg.waitForEvent(smalldbg::StopReason::ProcessCreated);
    TEST_ASSERT(reason == smalldbg::StopReason::ProcessCreated, "Expected ProcessCreated event", 18);
    TEST_PASS("ProcessCreated event received");
    
    std::cout << "\n=== Test 2: Verify Attached State ===" << std::endl;
    TEST_ASSERT(dbg.isAttached(), "Debugger should be attached", 3);
    TEST_PASS("Debugger is attached");
    
    auto pid = dbg.attachedPid();
    TEST_ASSERT(pid.has_value(), "Should have attached PID", 4);
    std::cout << "[INFO] Attached to PID: " << pid.value() << std::endl;
    TEST_PASS("PID retrieval successful");
    
    // Resume and wait for initial breakpoint
    dbg.resume();
    reason = dbg.waitForEvent(smalldbg::StopReason::InitialBreakpoint);
    TEST_ASSERT(reason == smalldbg::StopReason::InitialBreakpoint, "Expected InitialBreakpoint event", 19);
    TEST_PASS("InitialBreakpoint event received");
    
    return 0;
}

int test_register_access(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 3: Register Access ===" << std::endl;
    
    // Get the current stop address (should be at InitialBreakpoint)
    auto stopAddr = dbg.getStopAddress();
    
    smalldbg::Registers r;
    auto s = dbg.getRegisters(r);
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to get registers", 5);
    TEST_ASSERT(r.arch == smalldbg::Arch::X64, "Architecture mismatch", 6);
    
    std::cout << "[INFO] RIP: 0x" << std::hex << r.x64.rip << std::dec << std::endl;
    std::cout << "[INFO] Stop Address: 0x" << std::hex << stopAddr << std::dec << std::endl;
    
    // On Windows, RIP at initial breakpoint may be slightly past the exception address
    // Check that they're close (within a few bytes)
    int64_t diff = static_cast<int64_t>(r.x64.rip) - static_cast<int64_t>(stopAddr);
    TEST_ASSERT(diff >= -8 && diff <= 8, "RIP should be close to stop address", 20);
    
    // Basic sanity checks: stack pointer should be non-zero and aligned
    TEST_ASSERT(r.x64.rsp != 0, "RSP should be non-zero", 21);
    TEST_ASSERT((r.x64.rsp & 0xF) == 0 || (r.x64.rsp & 0xF) == 8, "RSP should be 16-byte aligned (or 8-byte offset)", 22);
    
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

int test_stack_trace_and_locals(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 7: Stack Trace and Local Variables ===" << std::endl;
    
    // Get current thread
    auto thread = dbg.getCurrentThread();
    TEST_ASSERT(thread != nullptr, "Failed to get current thread", 23);
    TEST_PASS("Got current thread");
    
    // Create stack trace
    smalldbg::StackTrace stackTrace(thread.get());
    auto s = stackTrace.unwind();
    TEST_ASSERT(s == smalldbg::Status::Ok, "Failed to unwind stack", 24);
    TEST_PASS("Stack unwinding successful");
    
    const auto& frames = stackTrace.getFrames();
    TEST_ASSERT(frames.size() > 0, "Should have at least one frame", 25);
    std::cout << "[INFO] Collected " << frames.size() << " frame(s)" << std::endl;
    TEST_PASS("Stack frames collected");
    
    // Check first frame has valid data
    const auto& frame0 = *frames[0];
    TEST_ASSERT(frame0.ip() != 0, "Frame 0 should have valid IP", 26);
    TEST_ASSERT(frame0.hasRegisters, "Frame 0 should have registers", 27);
    std::cout << "[INFO] Frame 0 IP: 0x" << std::hex << frame0.ip() << std::dec << std::endl;
    TEST_PASS("Frame 0 validated");
    
    // Check for local variables in at least one frame
    bool foundLocals = false;
    for (const auto& frame : frames) {
        if (!frame->localVariables.empty()) {
            foundLocals = true;
            std::cout << "[INFO] Found " << frame->localVariables.size() 
                     << " local variable(s) in a frame" << std::endl;
            
            // Validate first variable
            const auto& var = frame->localVariables[0];
            TEST_ASSERT(!var.name.empty(), "Variable should have a name", 28);
            TEST_ASSERT(var.size > 0, "Variable should have a size", 29);
            TEST_ASSERT(var.frame == frame.get(), "Variable should reference its frame", 30);
            
            std::cout << "[INFO] First variable: " << var.name 
                     << " (type=" << var.typeName 
                     << ", size=" << var.size << ")" << std::endl;
            TEST_PASS("Local variable validated");
            break;
        }
    }
    
    if (foundLocals) {
        TEST_PASS("Local variables found and validated");
    } else {
        std::cout << "[INFO] No local variables found (may be optimized out)" << std::endl;
    }
    
    return 0;
}

int test_logging(int logCount) {
    std::cout << "\n=== Test 8: Logging Callback ===" << std::endl;
    TEST_ASSERT(logCount > 0, "Should have received log messages", 15);
    std::cout << "[INFO] Total log messages received: " << logCount << std::endl;
    TEST_PASS("Logging callback functional");
    
    return 0;
}

int test_detach(smalldbg::Debugger &dbg) {
    std::cout << "\n=== Test 9: Detach ===" << std::endl;
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
    if ((result = test_stack_trace_and_locals(dbg)) != 0) return result;
    if ((result = test_logging(logCount)) != 0) return result;
    if ((result = test_detach(dbg)) != 0) return result;

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    return 0;
}
