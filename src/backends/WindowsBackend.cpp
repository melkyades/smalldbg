#include "WindowsBackend.h"
#include "../../include/smalldbg/Process.h"
#include "../../include/smalldbg/Thread.h"
#include "../../include/smalldbg/Debugger.h"
#include "../symbols/DbgHelpBackend.h"
#include <algorithm>
#include <cstring>
#include <windows.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>

namespace smalldbg {

WindowsBackend::WindowsBackend(Debugger* dbg, Mode m, Arch a) : Backend(dbg, m, a) {
    processAttachSem = CreateSemaphoreA(NULL, 0, 1, NULL);
}

WindowsBackend::~WindowsBackend() {
    // ensure debug thread is stopped and handles closed
    withStopLock([this]() { running = false; });
    stopCV.notify_all();
    if (debugThread.joinable()) debugThread.join();
    if (pi.hProcess) { CloseHandle(pi.hProcess); pi.hProcess = NULL; }
    if (pi.hThread) { CloseHandle(pi.hThread); pi.hThread = NULL; }
    if (processAttachSem) { CloseHandle(processAttachSem); processAttachSem = NULL; }
}

Status WindowsBackend::waitForProcessAttach() {
    if (WaitForSingleObject(processAttachSem, 5000) != WAIT_OBJECT_0) {
        if (log) log("(windows) timeout waiting for process attach/creation");
        withStopLock([this]() { running = false; });
        if (debugThread.joinable()) debugThread.join();
        return Status::Error;
    }
    
    if (!attached) {
        if (log) log("(windows) process attach/creation failed");
        withStopLock([this]() { running = false; });
        if (debugThread.joinable()) debugThread.join();
        return Status::Error;
    }
    
    return Status::Ok;
}

Status WindowsBackend::attach(int p) {
    if (attached) return Status::AlreadyAttached;

    // Attach using the Windows Debug API
    if (!DebugActiveProcess(p)) {
        return Status::Error;
    }
    pi.hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, p);
    if (!pi.hProcess) {
        DebugActiveProcessStop(p);
        return Status::Error;
    }

    pi.dwProcessId = p;
    attached = true;
    memory.assign(64*1024, 0);
    regs = Registers{};
    withStopLock([this]() { running = true; });
    debugThread = std::thread(&WindowsBackend::debugLoop, this);
    
    Status status = waitForProcessAttach();
    if (status != Status::Ok) return status;
    
    if (log) log("(windows) attached to pid " + std::to_string(p));
    return Status::Ok;
}

Status WindowsBackend::launch(const std::string &path, const std::vector<std::string> &args) {
    if (attached) return Status::Error;

    // Build command line
    std::string cmd = path;
    for (auto &a : args) {
        cmd += " ";
        cmd += a;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION localPi = {};

    // Start the debug thread first, then create the process from within it
    // This is required because debug events are delivered to the thread that creates the debugged process
    launchPath = cmd;
    withStopLock([this]() { running = true; });
    debugThread = std::thread(&WindowsBackend::debugLoop, this);
    
    Status status = waitForProcessAttach();
    if (status != Status::Ok) return status;
    
    if (log) log("(windows) launched " + path + " (pid=" + std::to_string(pi.dwProcessId) + ")");
    return Status::Ok;
}

Status WindowsBackend::detach() {
    if (!attached) return Status::NotAttached;
    
    // stop debug loop
    withStopLock([this]() { running = false; });
    stopCV.notify_all();

    // If we attached to an existing process, call DebugActiveProcessStop
    if (pi.dwProcessId > 0) DebugActiveProcessStop(pi.dwProcessId);

    if (debugThread.joinable()) debugThread.join();

    if (log) log(std::string("(windows) detached from pid ") + std::to_string(pi.dwProcessId));

    if (pi.hProcess) { CloseHandle(pi.hProcess); pi.hProcess = NULL; }
    if (pi.hThread) { CloseHandle(pi.hThread); pi.hThread = NULL; }

    attached = false;
    process.reset();
    {
        std::lock_guard<std::mutex> g(bpMutex);
        bpOriginal.clear();
        bps.clear();
    }

    return Status::Ok;
}

StopReason WindowsBackend::waitForEvent(StopReason reason, int timeout_ms) {
    if (!attached) return StopReason::None;
    
    std::unique_lock<std::mutex> lock(stopMutex);
    
    if (timeout_ms == 0) {
        // No wait - just check current state
        if (stopped && (reason == StopReason::None || stopReason == reason)) {
            return stopReason;
        }
        return StopReason::None;
    } else if (timeout_ms < 0) {
        // Infinite wait
        stopCV.wait(lock, [this, reason]() {
            return stopped && (reason == StopReason::None || stopReason == reason);
        });
        return stopReason;
    } else {
        // Timed wait
        bool result = stopCV.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this, reason]() {
            return stopped && (reason == StopReason::None || stopReason == reason);
        });
        return result ? stopReason : StopReason::None;
    }
}

Status WindowsBackend::resume() {
    if (!attached) return Status::NotAttached;
    
    // Signal the debug loop to continue
    withStopLock([this]() {
        continueRequested = true;
        stopReason = StopReason::None;
    });
    stopCV.notify_all();
    
    if (log) log("(windows) resume");
    return Status::Ok;
}

Status WindowsBackend::suspend() {
    if (!attached) return Status::NotAttached;
    
    // Use DebugBreakProcess to interrupt the running process
    if (!DebugBreakProcess(pi.hProcess)) {
        if (log) log("(windows) suspend failed");
        return Status::Error;
    }
    
    if (log) log("(windows) suspend requested");
    return Status::Ok;
}

Status WindowsBackend::step(Thread* thread) {
    if (!attached) return Status::NotAttached;

    // Thread is always non-null
    DWORD targetTid = static_cast<DWORD>(thread->getThreadId());

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) return Status::Error;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return Status::Error; }

    // Set trap flag in EFlags/RFlags
    ctx.EFlags |= 0x100;
    if (!SetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return Status::Error; }
    
    CloseHandle(hThread);
    
    // Signal continue
    withStopLock([this]() {
        continueRequested = true;
    });
    stopCV.notify_all();

    if (log) log("(windows) step requested");
    return Status::Ok;
}

Status WindowsBackend::setBreakpoint(Address addr, const std::string &name) {
    if (!attached) return Status::NotAttached;
    std::lock_guard<std::mutex> g(bpMutex);
    if (bpOriginal.find(addr) != bpOriginal.end()) return Status::Error; // already set

    uint8_t orig = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)addr, &orig, 1, &read) || read!=1) return Status::Error;

    uint8_t int3 = 0xCC;
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)addr, &int3, 1, &written) || written!=1) return Status::Error;
    FlushInstructionCache(pi.hProcess, (LPCVOID)addr, 1);

    bpOriginal[addr] = orig;
    Breakpoint b; b.addr = addr; b.enabled = true; b.name = name;
    bps.push_back(b);
    if (log) log("(windows) breakpoint set at 0x" + std::to_string(addr));
    return Status::Ok;
}

Status WindowsBackend::clearBreakpoint(Address addr) {
    if (!attached) return Status::NotAttached;
    std::lock_guard<std::mutex> g(bpMutex);
    auto itOrig = bpOriginal.find(addr);
    if (itOrig == bpOriginal.end()) return Status::NotFound;

    uint8_t orig = itOrig->second;
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)addr, &orig, 1, &written) || written != 1) return Status::Error;
    FlushInstructionCache(pi.hProcess, (LPCVOID)addr, 1);
    bpOriginal.erase(itOrig);

    auto pred = [&](const Breakpoint &b){return b.addr==addr;};
    auto it = std::remove_if(bps.begin(), bps.end(), pred);
    if (it != bps.end()) bps.erase(it, bps.end());

    if (log) log("(windows) breakpoint cleared at 0x" + std::to_string(addr));
    return Status::Ok;
}

std::vector<Breakpoint> WindowsBackend::listBreakpoints() const {
    return bps;
}

Status WindowsBackend::readMemory(Address address, void *outBuf, size_t size) const {
    if (!attached) return Status::NotAttached;
    SIZE_T read = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)address, outBuf, size, &read) || read != size) return Status::NotFound;
    return Status::Ok;
}

Status WindowsBackend::writeMemory(Address address, const void *data, size_t size) {
    if (!attached) return Status::NotAttached;
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)address, data, size, &written) || written != size) return Status::NotFound;
    FlushInstructionCache(pi.hProcess, (LPCVOID)address, size);
    return Status::Ok;
}

Status WindowsBackend::getRegisters(Thread* thread, Registers &out) const {
    if (!attached) return Status::NotAttached;

    // Thread is always non-null
    DWORD targetTid = static_cast<DWORD>(thread->getThreadId());

    CONTEXT ctx = {};
    if (!captureThreadContext(targetTid, ctx)) return Status::Error;

    return contextToRegisters(ctx, out);
}

bool WindowsBackend::captureThreadContext(DWORD tid, CONTEXT &ctx) const {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) return false;

        std::memset(&ctx, 0, sizeof(ctx));
    #ifdef CONTEXT_ALL
        ctx.ContextFlags = CONTEXT_ALL;
    #else
        ctx.ContextFlags = CONTEXT_FULL;
    #endif
        bool ok = GetThreadContext(hThread, &ctx) != 0;
        CloseHandle(hThread);
        return ok;
}

Status WindowsBackend::contextToRegisters(const CONTEXT &ctx, Registers &out) const {
        if (arch == Arch::X64) {
            out.arch = Arch::X64;
            auto &r = out.x64;
            r.rip = ctx.Rip;
            r.rsp = ctx.Rsp;
            r.rbp = ctx.Rbp;
            r.rflags = ctx.EFlags;
            r.rax = ctx.Rax;
            r.rbx = ctx.Rbx;
            r.rcx = ctx.Rcx;
            r.rdx = ctx.Rdx;
            r.rsi = ctx.Rsi;
            r.rdi = ctx.Rdi;
            r.r8  = ctx.R8;
            r.r9  = ctx.R9;
            r.r10 = ctx.R10;
            r.r11 = ctx.R11;
            r.r12 = ctx.R12;
            r.r13 = ctx.R13;
            r.r14 = ctx.R14;
            r.r15 = ctx.R15;
            r.cs = static_cast<uint16_t>(ctx.SegCs);
            r.ds = static_cast<uint16_t>(ctx.SegDs);
            r.es = static_cast<uint16_t>(ctx.SegEs);
            r.fs = static_cast<uint16_t>(ctx.SegFs);
            r.gs = static_cast<uint16_t>(ctx.SegGs);
            r.ss = static_cast<uint16_t>(ctx.SegSs);
            r.fsBase = 0;
            r.gsBase = 0;
            r.dr0 = ctx.Dr0;
            r.dr1 = ctx.Dr1;
            r.dr2 = ctx.Dr2;
            r.dr3 = ctx.Dr3;
            r.dr6 = ctx.Dr6;
            r.dr7 = ctx.Dr7;
            r.mxcsr = ctx.MxCsr;

            const M128A* xmmRegs[] = {&ctx.Xmm0,&ctx.Xmm1,&ctx.Xmm2,&ctx.Xmm3,&ctx.Xmm4,&ctx.Xmm5,&ctx.Xmm6,&ctx.Xmm7,
                                      &ctx.Xmm8,&ctx.Xmm9,&ctx.Xmm10,&ctx.Xmm11,&ctx.Xmm12,&ctx.Xmm13,&ctx.Xmm14,&ctx.Xmm15};
            for (size_t i = 0; i < 16; ++i) {
                r.xmm[i].low = xmmRegs[i]->Low;
                r.xmm[i].high = xmmRegs[i]->High;
            }

            r.fpControl = ctx.FltSave.ControlWord;
            r.fpStatus = ctx.FltSave.StatusWord;
            r.fpTag = ctx.FltSave.TagWord;
            for (size_t i = 0; i < 8; ++i) {
                std::memcpy(r.st[i].bytes.data(), &ctx.FltSave.FloatRegisters[i], r.st[i].bytes.size());
            }

            r.pc = ctx.Rip;
            r.sp = ctx.Rsp;
            return Status::Ok;
        } else if (arch == Arch::ARM64) {
            out.arch = Arch::ARM64;
    #if defined(_M_ARM64)
            auto &r = out.arm64;
            r.x0 = ctx.Arm64.X0; r.x1 = ctx.Arm64.X1; r.x2 = ctx.Arm64.X2; r.x3 = ctx.Arm64.X3;
            r.x4 = ctx.Arm64.X4; r.x5 = ctx.Arm64.X5; r.x6 = ctx.Arm64.X6; r.x7 = ctx.Arm64.X7;
            r.x8 = ctx.Arm64.X8; r.x9 = ctx.Arm64.X9; r.x10 = ctx.Arm64.X10; r.x11 = ctx.Arm64.X11;
            r.x12 = ctx.Arm64.X12; r.x13 = ctx.Arm64.X13; r.x14 = ctx.Arm64.X14; r.x15 = ctx.Arm64.X15;
            r.x16 = ctx.Arm64.X16; r.x17 = ctx.Arm64.X17; r.x18 = ctx.Arm64.X18; r.x19 = ctx.Arm64.X19;
            r.x20 = ctx.Arm64.X20; r.x21 = ctx.Arm64.X21; r.x22 = ctx.Arm64.X22; r.x23 = ctx.Arm64.X23;
            r.x24 = ctx.Arm64.X24; r.x25 = ctx.Arm64.X25; r.x26 = ctx.Arm64.X26; r.x27 = ctx.Arm64.X27;
            r.x28 = ctx.Arm64.X28; r.x29_fp = ctx.Arm64.Fp; r.x30_lr = ctx.Arm64.Lr;
            r.sp = ctx.Arm64.Sp; r.pc = ctx.Arm64.Pc;
            return Status::Ok;
    #else
            (void)ctx;
            return Status::Error;
    #endif
        }

        return Status::Error;
    }

Status WindowsBackend::recoverCallerRegisters(Registers& regs) const {
    if (arch != Arch::X64) {
        // Only X64 supported for now
        return Status::Error;
    }
    
    // Use RtlLookupFunctionEntry and RtlVirtualUnwind
    // to properly restore all registers using .pdata unwind information
    
    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION func = RtlLookupFunctionEntry(regs.x64.rip, &imageBase, NULL);
    
    if (!func) {
        // No unwind info available - likely a leaf function or no .pdata
        return Status::Error;
    }
    
    // Save original RIP to detect if unwinding actually changed anything
    Address originalRip = regs.x64.rip;
    
    // Set up CONTEXT structure with current register values
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    context.Rip = regs.x64.rip;
    context.Rsp = regs.x64.rsp;
    context.Rbp = regs.x64.rbp;
    context.Rax = regs.x64.rax;
    context.Rbx = regs.x64.rbx;
    context.Rcx = regs.x64.rcx;
    context.Rdx = regs.x64.rdx;
    context.Rsi = regs.x64.rsi;
    context.Rdi = regs.x64.rdi;
    context.R8 = regs.x64.r8;
    context.R9 = regs.x64.r9;
    context.R10 = regs.x64.r10;
    context.R11 = regs.x64.r11;
    context.R12 = regs.x64.r12;
    context.R13 = regs.x64.r13;
    context.R14 = regs.x64.r14;
    context.R15 = regs.x64.r15;
    context.EFlags = static_cast<DWORD>(regs.x64.rflags);
    
    // Perform virtual unwind
    PVOID handlerData = NULL;
    DWORD64 establisherFrame = 0;
    
    __try {
        RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,      // We don't need exception handler info
            imageBase,
            context.Rip,
            func,
            &context,
            &handlerData,
            &establisherFrame,
            NULL
        );
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Virtual unwind failed
        return Status::Error;
    }
    
    // Check if unwinding actually did something (RIP should have changed)
    if (context.Rip == 0 || context.Rip == originalRip) {
        // Unwinding failed or didn't progress
        return Status::Error;
    }
    
    // Update our register structure with unwound values
    // Note: RtlVirtualUnwind restores callee-saved registers and updates
    // RIP/RSP to point to the caller's context
    regs.x64.rip = context.Rip;
    regs.x64.rsp = context.Rsp;
    regs.x64.rbp = context.Rbp;
    regs.x64.rbx = context.Rbx;
    regs.x64.rsi = context.Rsi;
    regs.x64.rdi = context.Rdi;
    regs.x64.r12 = context.R12;
    regs.x64.r13 = context.R13;
    regs.x64.r14 = context.R14;
    regs.x64.r15 = context.R15;
    
    // Note: Volatile registers (rax, rcx, rdx, r8-r11) are NOT restored
    // as they are caller-saved and may not be preserved across calls
    
    return Status::Ok;
}

bool WindowsBackend::createProcessForDebug() {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);

    // Extract working directory from the exe path
    std::string workDir;
    size_t lastSlash = launchPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        workDir = launchPath.substr(0, lastSlash);
    }
    const char* workDirPtr = workDir.empty() ? nullptr : workDir.c_str();

    BOOL result = CreateProcessA(nullptr, const_cast<char*>(launchPath.c_str()), nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS, nullptr, workDirPtr, &si, &pi);
    if (!result) {
        DWORD err = GetLastError();
        if (log) log("(windows) CreateProcess failed, error=" + std::to_string(err));
        // Signal failure so launch() doesn't wait
        ReleaseSemaphore(processAttachSem, 1, NULL);
        return false;
    }

    attached = true;
    memory.assign(64*1024, 0);
    regs = Registers{};
    exePath = launchPath;  // Save the exe path before clearing
    launchPath.clear(); // Clear so we don't try to launch again
    return true;
}

void WindowsBackend::debugLoop() {
    // If launchPath is set, create the process from this thread
    if (!launchPath.empty()) {
        if (!createProcessForDebug()) {
            withStopLock([this]() { running = false; });
            return;
        }
    }
    
    DEBUG_EVENT ev;
    bool keepRunning = true;
    while (keepRunning) {
        {
            std::lock_guard<std::mutex> lock(stopMutex);
            keepRunning = running;
        }
        if (!WaitForDebugEvent(&ev, 500)) {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT) continue;
            break;
        }

        bool shouldContinue = false;
        DWORD continueStatus = DBG_CONTINUE;
        
        // Log all events with their type codes
        const char* eventName = "UNKNOWN";
        switch (ev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: eventName = "EXCEPTION"; break;
        case CREATE_THREAD_DEBUG_EVENT: eventName = "CREATE_THREAD"; break;
        case CREATE_PROCESS_DEBUG_EVENT: eventName = "CREATE_PROCESS"; break;
        case EXIT_THREAD_DEBUG_EVENT: eventName = "EXIT_THREAD"; break;
        case EXIT_PROCESS_DEBUG_EVENT: eventName = "EXIT_PROCESS"; break;
        case LOAD_DLL_DEBUG_EVENT: eventName = "LOAD_DLL"; break;
        case UNLOAD_DLL_DEBUG_EVENT: eventName = "UNLOAD_DLL"; break;
        case OUTPUT_DEBUG_STRING_EVENT: eventName = "OUTPUT_DEBUG_STRING"; break;
        case RIP_EVENT: eventName = "RIP"; break;
        }
        if (log) {
            log(std::string("(windows) event=") + eventName + " code=" + std::to_string(ev.dwDebugEventCode) + " tid=" + std::to_string(ev.dwThreadId));
        }

        switch (ev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            shouldContinue = handleExceptionEvent(ev);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            handleThreadCreatedEvent(ev);
            shouldContinue = true;
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            shouldContinue = handleCreateProcessEvent(ev);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            handleExitProcessEvent(ev);
            shouldContinue = true;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            handleLoadDllEvent(ev);
            shouldContinue = true;
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            handleUnloadDllEvent(ev);
            shouldContinue = true;
            break;
        default:
            handleOtherDebugEvent(ev);
            shouldContinue = true;
            break;
        }

        if (!shouldContinue) {
            // Store the thread ID and stop - don't call ContinueDebugEvent yet
            // stopReason and stopAddress are already set by the handler
            withStopLock([this, &ev]() {
                stopThreadId = ev.dwThreadId;
                stopped = true;
                // stopReason and stopAddress are already set by handlers
            });
            
            // Set selected thread on debugger
            if (process) {
                auto threadOpt = process->getThread(static_cast<ThreadId>(ev.dwThreadId));
                if (threadOpt) {
                    debugger->setCurrentThread(*threadOpt);
                } else {
                    if (log) log(std::string("(windows) WARNING: thread not found in process: ") + std::to_string(ev.dwThreadId));
                }
            }
            
            // Notify anyone waiting for events
            stopCV.notify_all();
            
            // Notify via callback if set
            if (eventCallback) {
                eventCallback(stopReason, stopAddress);
            }
            
            // Wait until resume/step is called
            std::unique_lock<std::mutex> lock(stopMutex);
            stopCV.wait(lock, [this]() { return continueRequested || !running; });
            if (!running) break;
            continueRequested = false;
            stopped = false;
        }
        
        static std::atomic<int> continueCounter{0};
        int continueId = ++continueCounter;
        if (log) log("(windows) ContinueDebugEvent #" + std::to_string(continueId) + " pid=" + std::to_string(ev.dwProcessId) + " tid=" + std::to_string(ev.dwThreadId) + " status=" + std::to_string(continueStatus));
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    }
}

bool WindowsBackend::handleExceptionEvent(const DEBUG_EVENT &ev) {
    const auto &ex = ev.u.Exception.ExceptionRecord;
    DWORD code = ex.ExceptionCode;
    uintptr_t addr = reinterpret_cast<uintptr_t>(ex.ExceptionAddress);

    if (code == EXCEPTION_BREAKPOINT) {
        return handleBreakpointEvent(ev, addr);
    } else if (code == EXCEPTION_SINGLE_STEP) {
        return handleSingleStepEvent(ev);
    } else {
        // Other exceptions - stop for user to handle
        stopReason = StopReason::Exception;
        stopAddress = (Address)addr;
        if (log) log(std::string("(windows) EXCEPTION event code=") + std::to_string(code) + " at 0x" + std::to_string(addr));
        return false; // stop
    }
}

bool WindowsBackend::handleBreakpointEvent(const DEBUG_EVENT &ev, uintptr_t addr) {
    std::lock_guard<std::mutex> g(bpMutex);
    auto it = bpOriginal.find((Address)addr);
    if (it == bpOriginal.end()) {
        // Not our breakpoint - check if this is the initial loader breakpoint
        if (!seenInitialBreakpoint) {
            seenInitialBreakpoint = true;
            stopReason = StopReason::InitialBreakpoint;
            stopAddress = (Address)addr;
            if (log) log(std::string("(windows) BREAKPOINT (initial/loader) at 0x") + std::to_string(addr));
            return false; // stop on initial breakpoint
        } else {
            // Unknown system breakpoint after initialization
            stopReason = StopReason::Breakpoint;
            stopAddress = (Address)addr;
            if (log) log(std::string("(windows) BREAKPOINT (system/unknown) at 0x") + std::to_string(addr));
            return false; // stop on system breakpoint
        }
    }
    
    // Hit a user breakpoint - this is interesting, stop!
    stopReason = StopReason::Breakpoint;
    stopAddress = (Address)addr;
    
    // Restore original byte so the instruction can execute normally when resumed
    uint8_t orig = it->second;
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, (LPVOID)addr, &orig, 1, &written);
    FlushInstructionCache(pi.hProcess, (LPCVOID)addr, 1);

    // record that this thread must re-insert the INT3 after single-step
    pendingReinsert[ev.dwThreadId] = (Address)addr;

    // set trap flag on the thread so we get a SINGLE_STEP after the next instruction
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ev.dwThreadId);
    if (hThread) {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx)) {
            ctx.EFlags |= 0x100; // set trap flag
            SetThreadContext(hThread, &ctx);
        }
        CloseHandle(hThread);
    }

    if (log) log(std::string("(windows) BREAKPOINT handled at ") + std::to_string(addr) + " tid=" + std::to_string(ev.dwThreadId));
    return false; // stop on user breakpoint
}

bool WindowsBackend::handleSingleStepEvent(const DEBUG_EVENT &ev) {
    std::lock_guard<std::mutex> g(bpMutex);
    auto it = pendingReinsert.find(ev.dwThreadId);
    if (it != pendingReinsert.end()) {
        // This is a single-step after a breakpoint - re-insert the INT3
        Address baddr = it->second;
        uint8_t int3 = 0xCC;
        SIZE_T written = 0;
        WriteProcessMemory(pi.hProcess, (LPVOID)baddr, &int3, 1, &written);
        FlushInstructionCache(pi.hProcess, (LPCVOID)baddr, 1);
        pendingReinsert.erase(it);
        if (log) log(std::string("(windows) re-inserted INT3 at ") + std::to_string(baddr) + " for tid=" + std::to_string(ev.dwThreadId));
        return true; // continue after re-inserting breakpoint
    } else {
        // User-requested single-step - stop here
        stopReason = StopReason::SingleStep;
        stopAddress = 0; // We'd need to get thread context to get exact address
        if (log) log(std::string("(windows) SINGLE_STEP event pid=") + std::to_string(ev.dwProcessId) + " tid=" + std::to_string(ev.dwThreadId));
        return false; // stop on user single-step
    }
}

bool WindowsBackend::handleCreateProcessEvent(const DEBUG_EVENT &ev) {
    ThreadId mainThreadId = static_cast<ThreadId>(ev.dwThreadId);
    if (log) log(std::string("(windows) CREATE_PROCESS pid=") + std::to_string(ev.dwProcessId) + " main_tid=" + std::to_string(mainThreadId));
    
    // Create Process object
    process = std::make_shared<Process>(debugger, static_cast<int>(ev.dwProcessId));
    process->registerThread(mainThreadId);
    
    // Create and initialize DbgHelp backend now that we have a process handle
    auto dbgHelp = std::make_unique<DbgHelpBackend>();
    dbgHelpBackend = dbgHelp.get();  // Keep raw pointer
    
    auto* symProvider = debugger->getSymbolProvider();
    symProvider->addBackend(std::move(dbgHelp));  // Transfer ownership
    
    // Initialize the backend with current options
    dbgHelpBackend->initialize(pi.hProcess, symProvider->getOptions());
    
    // Notify DbgHelp backend about the main executable
    // Try to get exe name from the event, or use the launch path
    std::string imageName;
    char exeName[MAX_PATH] = {0};
    if (ev.u.CreateProcessInfo.lpImageName) {
        DWORD64 namePtr = 0;
        ReadProcessMemory(pi.hProcess, ev.u.CreateProcessInfo.lpImageName, &namePtr, sizeof(namePtr), NULL);
        
        if (namePtr) {
            if (ev.u.CreateProcessInfo.fUnicode) {
                wchar_t wideName[MAX_PATH];
                ReadProcessMemory(pi.hProcess, (LPCVOID)namePtr, wideName, sizeof(wideName), NULL);
                WideCharToMultiByte(CP_UTF8, 0, wideName, -1, exeName, sizeof(exeName), NULL, NULL);
            } else {
                ReadProcessMemory(pi.hProcess, (LPCVOID)namePtr, exeName, sizeof(exeName), NULL);
            }
        }
    }
    
    // If we didn't get a name from the event, use the saved exe path
    imageName = (exeName[0] != '\0') ? std::string(exeName) : exePath;
    
    dbgHelpBackend->registerModule(
        ev.u.CreateProcessInfo.hFile,
        ev.u.CreateProcessInfo.lpBaseOfImage,
        imageName,
        0  // Size not provided - DbgHelp will figure it out
    );
    
    // Close the file handle provided by the system
    if (ev.u.CreateProcessInfo.hFile) {
        CloseHandle(ev.u.CreateProcessInfo.hFile);
    }
    // Don't close hProcess/hThread - we may need them or they may be the same as pi handles
    
    // Signal that process has been created/attached
    ReleaseSemaphore(processAttachSem, 1, NULL);
    
    stopReason = StopReason::ProcessCreated;
    stopAddress = 0;
    return false; // stop so client can perform setup
}

void WindowsBackend::handleThreadCreatedEvent(const DEBUG_EVENT &ev) {
    // Close the thread handle provided by the system
    if (ev.u.CreateThread.hThread) {
        CloseHandle(ev.u.CreateThread.hThread);
    }
    
    ThreadId tid = static_cast<ThreadId>(ev.dwThreadId);
    if (log) log(std::string("(windows) CREATE_THREAD tid=") + std::to_string(tid));
    
    // Add thread directly to process
    if (process) {
        process->registerThread(tid);
    }
}

void WindowsBackend::handleExitProcessEvent(const DEBUG_EVENT &ev) {
    if (log) log(std::string("(windows) EXIT_PROCESS pid=") + std::to_string(ev.dwProcessId));
    withStopLock([this]() { running = false; });
    attached = false;
}

void WindowsBackend::handleLoadDllEvent(const DEBUG_EVENT &ev) {
    // Get DLL name if available
    char dllName[MAX_PATH] = {0};
    if (ev.u.LoadDll.lpImageName) {
        // Read the pointer to the name string
        DWORD64 namePtr = 0;
        ReadProcessMemory(pi.hProcess, ev.u.LoadDll.lpImageName, &namePtr, sizeof(namePtr), NULL);
        
        if (namePtr) {
            if (ev.u.LoadDll.fUnicode) {
                wchar_t wideName[MAX_PATH];
                ReadProcessMemory(pi.hProcess, (LPCVOID)namePtr, wideName, sizeof(wideName), NULL);
                WideCharToMultiByte(CP_UTF8, 0, wideName, -1, dllName, sizeof(dllName), NULL, NULL);
            } else {
                ReadProcessMemory(pi.hProcess, (LPCVOID)namePtr, dllName, sizeof(dllName), NULL);
            }
        }
    }
    
    if (log) {
        std::string msg = "(windows) LOAD_DLL base=0x" + 
                         std::to_string((uint64_t)ev.u.LoadDll.lpBaseOfDll);
        if (dllName[0]) {
            msg += " " + std::string(dllName);
        }
        log(msg);
    }
    
    // Notify DbgHelp backend
    dbgHelpBackend->registerModule(
        ev.u.LoadDll.hFile,
        ev.u.LoadDll.lpBaseOfDll,
        dllName,
        0  // Size not provided in event - DbgHelp will figure it out
    );
    
    // Close the file handle
    if (ev.u.LoadDll.hFile) {
        CloseHandle(ev.u.LoadDll.hFile);
    }
}

void WindowsBackend::handleUnloadDllEvent(const DEBUG_EVENT &ev) {
    if (log) {
        std::string msg = "(windows) UNLOAD_DLL base=0x" + 
                         std::to_string((uint64_t)ev.u.UnloadDll.lpBaseOfDll);
        log(msg);
    }
    
    // TODO: Could notify symbol provider to unload module symbols
}

void WindowsBackend::handleOtherDebugEvent(const DEBUG_EVENT &ev) {
    if (log) log("(windows) DEBUG_EVENT code=" + std::to_string(ev.dwDebugEventCode) + " pid=" + std::to_string(ev.dwProcessId) + " tid=" + std::to_string(ev.dwThreadId));
}

// isAttached() and attachedPid() are implemented inline in the header

} // namespace smalldbg
