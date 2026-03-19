// TTD (Time Travel Debugging) replay example
// This example demonstrates how to open and replay a TTD trace file (.run)
// using the DbgEng backend.
//
// Usage: ttd_replay <trace.run>
//
// To create a trace, use: ttd.exe -launch <app.exe> -out <trace.run>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

using namespace smalldbg;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string toHex(uint64_t val) {
    std::ostringstream os;
    os << std::hex << val;
    return os.str();
}

static void printRegisters(Debugger& dbg, Thread* thread) {
    Registers regs;
    if (dbg.getRegisters(thread, regs) != Status::Ok) return;

    std::cout << "  " << regs.arch->name()
              << "  IP=0x" << std::hex << regs.ip()
              << "  SP=0x" << regs.sp()
              << "  FP=0x" << regs.fp()
              << std::dec << std::endl;
}

static void printStackTrace(Debugger& dbg, Thread* thread) {
    auto* st = thread->getStackTrace(10);
    if (!st) {
        std::cout << "Failed to get stack trace" << std::endl;
        return;
    }
    st->unwind(10);
    const auto& frames = st->getFrames();
    std::cout << "Stack trace (" << frames.size() << " frames):" << std::endl;
    for (size_t i = 0; i < frames.size() && i < 10; i++) {
        const auto& f = frames[i];
        std::cout << "  [" << i << "] 0x" << std::hex << f->ip() << std::dec;
        if (!f->moduleName.empty() && f->moduleName != "<unknown>")
            std::cout << " " << f->moduleName << "!";
        if (!f->functionName.empty()) {
            std::cout << f->functionName;
            if (f->functionOffset)
                std::cout << "+0x" << std::hex << f->functionOffset << std::dec;
        }
        std::cout << std::endl;
    }
    delete st;
}

// ---------------------------------------------------------------------------
// Test phases
// ---------------------------------------------------------------------------

static void testForwardSteps(Debugger& dbg, Thread* thread, int count) {
    std::cout << "\n=== Step forward (" << count << " steps) ===" << std::endl;
    for (int i = 0; i < count; i++) {
        std::cout << "Step " << (i + 1) << ":" << std::endl;
        if (dbg.step(thread) != Status::Ok) {
            std::cerr << "  step() failed" << std::endl;
            break;
        }
        auto reason = dbg.waitForEvent(StopReason::None, 5000);
        if (reason == StopReason::None) {
            std::cerr << "  waitForEvent timeout" << std::endl;
            break;
        }
        printRegisters(dbg, thread);
    }
}

static void testResumeForward(Debugger& dbg, Thread* thread) {
    std::cout << "\n=== Resume forward ===" << std::endl;
    if (dbg.resume() != Status::Ok) {
        std::cerr << "  resume() failed" << std::endl;
        return;
    }
    auto reason = dbg.waitForEvent(StopReason::None, 10000);
    std::cout << "Stopped, reason=" << static_cast<int>(reason) << std::endl;
    printRegisters(dbg, thread);
}

static void testForwardAtEnd(Debugger& dbg, Thread* thread) {
    std::cout << "\n=== Step forward at end of trace ===" << std::endl;
    for (int i = 0; i < 2; i++) {
        std::cout << "Step " << (i + 1) << ":" << std::endl;
        if (dbg.step(thread) != Status::Ok) {
            std::cerr << "  step() failed" << std::endl;
            break;
        }
        auto reason = dbg.waitForEvent(StopReason::None, 5000);
        std::cout << "  reason=" << static_cast<int>(reason) << std::endl;
        if (reason == StopReason::ProcessExit) {
            std::cout << "  End of trace reached." << std::endl;
            break;
        }
        printRegisters(dbg, thread);
    }
}

// Reverse-continue with a watchpoint to find when g_test_value was last
// written with a particular value.  Uses DbgEng's "ba w4" (break on write,
// 4 bytes) hardware watchpoint, then repeatedly reverse-resumes — each hit
// stops at the instruction that wrote the variable.  Much faster than
// single-stepping backwards.
static void testReverseWatchpoint(Debugger& dbg, Thread* thread) {
    std::cout << "\n=== Reverse watchpoint: find g_test_value == 100 ===" << std::endl;

    // Resolve the address of g_test_value
    auto* syms = dbg.getSymbolProvider();
    auto sym = syms->getSymbolByName("g_test_value");
    if (!sym) sym = syms->getSymbolByName("*!g_test_value");
    if (!sym) sym = syms->getSymbolByName("test_target!g_test_value");
    if (!sym) {
        std::cerr << "  Symbol 'g_test_value' not found — skipping" << std::endl;
        return;
    }
    Address varAddr = sym->address;
    std::cout << "  g_test_value at 0x" << std::hex << varAddr << std::dec << std::endl;

    // Set a hardware watchpoint (write, 4 bytes) on the variable
    std::string baCmd = "ba w4 0x" + toHex(varAddr);
    std::cout << "  watchpoint: " << baCmd << std::endl;
    dbg.executeCommand(baCmd);

    constexpr int target = 100;
    constexpr int maxIter = 50;

    for (int i = 0; i < maxIter; i++) {
        if (dbg.reverseResume() != Status::Ok) {
            std::cerr << "  reverseResume() failed at iteration " << i << std::endl;
            break;
        }
        auto reason = dbg.waitForEvent(StopReason::None, 30000);
        if (reason == StopReason::None) {
            std::cerr << "  timeout at iteration " << i << std::endl;
            break;
        }

        int32_t val = 0;
        if (dbg.readMemory(varAddr, &val, sizeof(val)) != Status::Ok) {
            std::cerr << "  readMemory failed at iteration " << i << std::endl;
            break;
        }
        std::cout << "  [" << i << "] g_test_value = " << val << std::endl;

        if (val == target) {
            std::cout << "  Found g_test_value == " << target
                      << " after " << (i + 1) << " watchpoint hits" << std::endl;
            printRegisters(dbg, thread);
            printStackTrace(dbg, thread);
            dbg.executeCommand("bc *");
            return;
        }

        if (reason == StopReason::ProcessExit) {
            std::cout << "  Start of trace reached at iteration " << i << std::endl;
            break;
        }
    }

    dbg.executeCommand("bc *");
    std::cout << "  g_test_value == " << target << " not found within "
              << maxIter << " iterations" << std::endl;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

static Debugger createDebugger() {
#if defined(_M_ARM64)
    return Debugger(Mode::External, ARM64::instance());
#elif defined(_M_X64)
    return Debugger(Mode::External, X64::instance());
#else
    return Debugger(Mode::External, X86::instance());
#endif
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <trace.run>" << std::endl;
        std::cerr << "\nTo create a TTD trace:" << std::endl;
        std::cerr << "  ttd.exe -launch <app.exe> -out <trace.run>" << std::endl;
        return 1;
    }

    const char* tracePath = argv[1];

    std::cout << "=== TTD Replay ===" << std::endl;
    std::cout << "Trace: " << tracePath << std::endl;

    auto dbg = createDebugger();
    dbg.setLogCallback([](const std::string& msg) {
        std::cout << "[LOG] " << msg << std::endl;
    });

    if (dbg.openTrace(tracePath) != Status::Ok) {
        std::cerr << "Failed to open trace" << std::endl;
        return 1;
    }

    std::cout << "Trace opened (TTD=" << (dbg.isTTDTrace() ? "yes" : "no") << ")" << std::endl;

    auto proc = dbg.getProcess();
    if (!proc) { std::cerr << "No process" << std::endl; return 1; }
    auto thread = proc->primaryThread();
    if (!thread) { std::cerr << "No primary thread" << std::endl; return 1; }

    std::cout << "\n=== Initial Position ===" << std::endl;
    printRegisters(dbg, thread.get());
    printStackTrace(dbg, thread.get());

    testForwardSteps(dbg, thread.get(), 5);
    testResumeForward(dbg, thread.get());
    testForwardAtEnd(dbg, thread.get());

    testReverseWatchpoint(dbg, thread.get());

    dbg.detach();
    std::cout << "\nDone!" << std::endl;
    return 0;
}

