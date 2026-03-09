#include "WindowsBackend.h"
#include "../../include/smalldbg/Process.h"
#include "../../include/smalldbg/Thread.h"
#include "../../include/smalldbg/Debugger.h"
#include "../symbols/DbgHelpBackend.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <windows.h>
#include <DbgHelp.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>

namespace smalldbg {

// Single-step flag constants
constexpr DWORD X86_EFLAGS_TRAP_FLAG = 0x100;      // x86/x64 trap flag (bit 8)
constexpr DWORD ARM64_CPSR_SS_BIT = 0x200000;  // ARM64 single-step bit (bit 21)

WindowsBackend::WindowsBackend(Debugger* dbg, Mode m, const Arch* a) : Backend(dbg, m, a) {
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

Status WindowsBackend::attach(uintptr_t p) {
    if (attached) return Status::AlreadyAttached;

    // First, open the process handle
    DWORD dwPid = static_cast<DWORD>(p);
    pi.hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, dwPid);
    if (!pi.hProcess) {
        DWORD err = GetLastError();
        if (log) log("(windows) OpenProcess failed for PID " + std::to_string(p) + ", error=" + std::to_string(err));
        return Status::Error;
    }

    // Attach using the Windows Debug API
    if (!DebugActiveProcess(dwPid)) {
        DWORD err = GetLastError();
        if (log) log("(windows) DebugActiveProcess failed for PID " + std::to_string(p) + ", error=" + std::to_string(err));
        CloseHandle(pi.hProcess);
        pi.hProcess = NULL;
        return Status::Error;
    }

    pi.dwProcessId = dwPid;
    attached = true;
    memory.assign(64*1024, 0);
    regs = Registers{};
    withStopLock([this]() { running = true; });
    debugThread = std::thread(&WindowsBackend::debugLoop, this);
    
    Status status = waitForProcessAttach();
    if (status != Status::Ok) {
        if (pi.hProcess) {
            CloseHandle(pi.hProcess);
            pi.hProcess = NULL;
        }
        return status;
    }
    
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

    bool ok = withSuspendedThread(targetTid, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, [&](HANDLE hThread) {
        if (isWow64()) {
            WOW64_CONTEXT wow64Ctx = {};
            wow64Ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (!Wow64GetThreadContext(hThread, &wow64Ctx)) return false;
            wow64Ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
            return Wow64SetThreadContext(hThread, &wow64Ctx) != 0;
        } else {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (!GetThreadContext(hThread, &ctx)) return false;
#if defined(_M_X64)
            ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
#elif defined(_M_ARM64)
            ctx.Cpsr |= ARM64_CPSR_SS_BIT;
#elif defined(_M_IX86)
            ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
#endif
            return SetThreadContext(hThread, &ctx) != 0;
        }
    });
    if (!ok) return Status::Error;
    
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
    if (!attached) {
        if (log) log("(windows) getRegisters: not attached");
        return Status::NotAttached;
    }

    if (log) log("(windows) getRegisters: reading thread " + std::to_string(thread->getThreadId()));

    bool ok = isWow64()
        ? captureWow64Registers(thread, out)
        : captureNativeRegisters(thread, out);
    if (!ok) {
        if (log) log("(windows) getRegisters: capture failed");
        return Status::Error;
    }
    return Status::Ok;
}

Status WindowsBackend::getNativeRegisters(Thread* thread, Registers &out) const {
    if (!attached) return Status::NotAttached;

    // For non-WoW64 processes the native context IS the regular context.
    if (!isWow64())
        return getRegisters(thread, out);

    return captureNativeRegisters(thread, out) ? Status::Ok : Status::Error;
}
bool WindowsBackend::withSuspendedThread(DWORD tid, DWORD access, const std::function<bool(HANDLE)>& func) const {
    HANDLE hThread = OpenThread(access | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) {
        if (log) log("(windows) withSuspendedThread: OpenThread failed, error=" + std::to_string(GetLastError()));
        return false;
    }
    DWORD prev = SuspendThread(hThread);
    if (prev == (DWORD)-1) {
        if (log) log("(windows) withSuspendedThread: SuspendThread failed");
        CloseHandle(hThread);
        return false;
    }
    bool ok = func(hThread);
    ResumeThread(hThread);
    CloseHandle(hThread);
    return ok;
}

bool WindowsBackend::isWow64() const {
#if defined(_M_X64) || defined(_M_ARM64)
    return arch->pointerSize() == 4; // 64-bit debugger with 32-bit target is WoW64
#else
    return false;
#endif
}

bool WindowsBackend::captureWow64Registers(Thread* thread, Registers &out) const {
    DWORD tid = static_cast<DWORD>(thread->getThreadId());
    WOW64_CONTEXT wow64Ctx = {};
    wow64Ctx.ContextFlags = WOW64_CONTEXT_FULL;

    bool ok = withSuspendedThread(tid, THREAD_GET_CONTEXT, [&](HANDLE hThread) {
        return Wow64GetThreadContext(hThread, &wow64Ctx) != 0;
    });
    if (!ok) return false;

    return wow64ContextToRegisters(wow64Ctx, out) == Status::Ok;
}

Status WindowsBackend::wow64ContextToRegisters(const WOW64_CONTEXT &ctx, Registers &out) const {
    out.arch = X86::instance();
    auto &r = out.x86;
    r.eip = ctx.Eip;
    r.esp = ctx.Esp;
    r.ebp = ctx.Ebp;
    r.eflags = ctx.EFlags;
    r.eax = ctx.Eax;
    r.ebx = ctx.Ebx;
    r.ecx = ctx.Ecx;
    r.edx = ctx.Edx;
    r.esi = ctx.Esi;
    r.edi = ctx.Edi;
    r.cs = static_cast<uint16_t>(ctx.SegCs);
    r.ds = static_cast<uint16_t>(ctx.SegDs);
    r.es = static_cast<uint16_t>(ctx.SegEs);
    r.fs = static_cast<uint16_t>(ctx.SegFs);
    r.gs = static_cast<uint16_t>(ctx.SegGs);
    r.ss = static_cast<uint16_t>(ctx.SegSs);
    return Status::Ok;
}

bool WindowsBackend::captureNativeRegisters(Thread* thread, Registers &out) const {
    DWORD tid = static_cast<DWORD>(thread->getThreadId());
    CONTEXT ctx = {};
#ifdef CONTEXT_ALL
    ctx.ContextFlags = CONTEXT_ALL;
#else
    ctx.ContextFlags = CONTEXT_FULL;
#endif
    bool ok = withSuspendedThread(tid, THREAD_GET_CONTEXT, [&](HANDLE hThread) {
        return GetThreadContext(hThread, &ctx) != 0;
    });
    if (!ok) return false;

    return nativeContextToRegisters(ctx, out) == Status::Ok;
}

Status WindowsBackend::nativeContextToRegisters(const CONTEXT &ctx, Registers &out) const {
    #if defined(_M_X64)
            out.arch = X64::instance();
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
    #elif defined(_M_ARM64)
            out.arch = ARM64::instance();
            auto &r = out.arm64;
            // Native ARM64 CONTEXT has X0-X28, Fp, Lr, Sp, Pc directly (no Arm64. prefix)
            r.x0 = ctx.X0; r.x1 = ctx.X1; r.x2 = ctx.X2; r.x3 = ctx.X3;
            r.x4 = ctx.X4; r.x5 = ctx.X5; r.x6 = ctx.X6; r.x7 = ctx.X7;
            r.x8 = ctx.X8; r.x9 = ctx.X9; r.x10 = ctx.X10; r.x11 = ctx.X11;
            r.x12 = ctx.X12; r.x13 = ctx.X13; r.x14 = ctx.X14; r.x15 = ctx.X15;
            r.x16 = ctx.X16; r.x17 = ctx.X17; r.x18 = ctx.X18; r.x19 = ctx.X19;
            r.x20 = ctx.X20; r.x21 = ctx.X21; r.x22 = ctx.X22; r.x23 = ctx.X23;
            r.x24 = ctx.X24; r.x25 = ctx.X25; r.x26 = ctx.X26; r.x27 = ctx.X27;
            r.x28 = ctx.X28; r.x29_fp = ctx.Fp; r.x30_lr = ctx.Lr;
            r.sp = ctx.Sp; r.pc = ctx.Pc;
            return Status::Ok;
    #elif defined(_M_IX86)
            out.arch = X86::instance();
            auto &r = out.x86;
            r.eip = ctx.Eip;
            r.esp = ctx.Esp;
            r.ebp = ctx.Ebp;
            r.eflags = ctx.EFlags;
            r.eax = ctx.Eax;
            r.ebx = ctx.Ebx;
            r.ecx = ctx.Ecx;
            r.edx = ctx.Edx;
            r.esi = ctx.Esi;
            r.edi = ctx.Edi;
            r.cs = static_cast<uint16_t>(ctx.SegCs);
            r.ds = static_cast<uint16_t>(ctx.SegDs);
            r.es = static_cast<uint16_t>(ctx.SegEs);
            r.fs = static_cast<uint16_t>(ctx.SegFs);
            r.gs = static_cast<uint16_t>(ctx.SegGs);
            r.ss = static_cast<uint16_t>(ctx.SegSs);
            return Status::Ok;
    #else
            #error "Unsupported architecture"
    #endif
    }

Status WindowsBackend::recoverCallerRegisters(Registers& regs) const {
    // Dispatch on the *registers'* architecture, not the backend's.
    // This lets callers unwind native (x64) frames even when the
    // backend targets a WoW64 (x86) process.

    if (regs.arch == X86::instance()) {
        // Use StackWalk64 with IMAGE_FILE_MACHINE_I386.
        // This works for WOW64 processes: it reads FPO data from PDBs
        // (via SymFunctionTableAccess64) and uses ReadProcessMemory to
        // walk the target process stack.
        STACKFRAME64 sf = {};
        sf.AddrPC.Offset    = regs.x86.eip;
        sf.AddrPC.Mode      = AddrModeFlat;
        sf.AddrFrame.Offset = regs.x86.ebp;
        sf.AddrFrame.Mode   = AddrModeFlat;
        sf.AddrStack.Offset = regs.x86.esp;
        sf.AddrStack.Mode   = AddrModeFlat;

        BOOL ok = StackWalk64(
            IMAGE_FILE_MACHINE_I386,
            pi.hProcess,
            NULL,                           // hThread (not needed)
            &sf,
            NULL,                           // context (not needed for I386)
            NULL,                           // ReadMemoryRoutine (default)
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL                            // TranslateAddress
        );

        if (!ok || sf.AddrPC.Offset == 0)
            return Status::Error;

        regs.x86.eip = static_cast<uint32_t>(sf.AddrPC.Offset);
        regs.x86.ebp = static_cast<uint32_t>(sf.AddrFrame.Offset);
        regs.x86.esp = static_cast<uint32_t>(sf.AddrStack.Offset);
        return Status::Ok;
    }

#if defined(_M_X64)
    // x64 stack unwinding - native x64 host
    if (regs.arch == X64::instance()) {
        // Use StackWalk64 with IMAGE_FILE_MACHINE_AMD64.
        // AMD64 StackWalk64 requires a valid CONTEXT pointer.
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_CONTROL;
        ctx.Rip = regs.x64.rip;
        ctx.Rsp = regs.x64.rsp;
        ctx.Rbp = regs.x64.rbp;

        STACKFRAME64 sf = {};
        sf.AddrPC.Offset    = regs.x64.rip;
        sf.AddrPC.Mode      = AddrModeFlat;
        sf.AddrFrame.Offset = regs.x64.rbp;
        sf.AddrFrame.Mode   = AddrModeFlat;
        sf.AddrStack.Offset = regs.x64.rsp;
        sf.AddrStack.Mode   = AddrModeFlat;

        BOOL ok = StackWalk64(
            IMAGE_FILE_MACHINE_AMD64,
            pi.hProcess,
            NULL,
            &sf,
            &ctx,
            NULL,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL
        );

        if (!ok || sf.AddrPC.Offset == 0)
            return Status::Error;

        regs.x64.rip = sf.AddrPC.Offset;
        regs.x64.rbp = sf.AddrFrame.Offset;
        regs.x64.rsp = sf.AddrStack.Offset;
        return Status::Ok;
    }
#elif defined(_M_ARM64)
    // x64 stack unwinding from ARM64 host (e.g., for x64 emulated processes)
    // StackWalk64 can work without a CONTEXT pointer if we fill STACKFRAME64 properly
    if (regs.arch == X64::instance()) {
        STACKFRAME64 sf = {};
        sf.AddrPC.Offset    = regs.x64.rip;
        sf.AddrPC.Mode      = AddrModeFlat;
        sf.AddrFrame.Offset = regs.x64.rbp;
        sf.AddrFrame.Mode   = AddrModeFlat;
        sf.AddrStack.Offset = regs.x64.rsp;
        sf.AddrStack.Mode   = AddrModeFlat;

        BOOL ok = StackWalk64(
            IMAGE_FILE_MACHINE_AMD64,
            pi.hProcess,
            NULL,
            &sf,
            NULL,  // No context pointer available on ARM64 host
            NULL,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL
        );

        if (!ok || sf.AddrPC.Offset == 0)
            return Status::Error;

        regs.x64.rip = sf.AddrPC.Offset;
        regs.x64.rbp = sf.AddrFrame.Offset;
        regs.x64.rsp = sf.AddrStack.Offset;
        return Status::Ok;
    }
#endif

    return Status::Error;
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
    } else {
        if (log) log("(windows) debugLoop started for attach, waiting for events...");
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
        
        // Clear the continue flag now that we have an event to process
        // This ensures that when we wait for resume/step later, the flag is false
        {
            std::lock_guard<std::mutex> lock(stopMutex);
            continueRequested = false;
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

        shouldContinue = true;  // Default to continue; handlers return false to stop
        switch (ev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            shouldContinue = handleExceptionEvent(ev);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            handleThreadCreatedEvent(ev);
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            shouldContinue = handleCreateProcessEvent(ev);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            handleExitProcessEvent(ev);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            handleLoadDllEvent(ev);
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            handleUnloadDllEvent(ev);
            break;
        default:
            handleOtherDebugEvent(ev);
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
        }

            // Notify via callback if set
        if (eventCallback) {
            shouldContinue = eventCallback(stopReason, stopAddress);
        }
       
        if (!shouldContinue) {
            // Notify anyone waiting for events
            stopCV.notify_all();
            
            
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
        if (arch == X86::instance()) {
            // WOW64 x86 process: use Wow64Get/SetThreadContext
            WOW64_CONTEXT wow64Ctx = {};
            wow64Ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (Wow64GetThreadContext(hThread, &wow64Ctx)) {
                wow64Ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
                Wow64SetThreadContext(hThread, &wow64Ctx);
            }
        } else {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
    #if defined(_M_X64)
                ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
    #elif defined(_M_ARM64)
                ctx.Cpsr |= ARM64_CPSR_SS_BIT;
    #elif defined(_M_IX86)
                ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
    #endif
                SetThreadContext(hThread, &ctx);
            }
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
    initProcess(static_cast<uintptr_t>(ev.dwProcessId));
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
        bool is64bitModule = (uint64_t)ev.u.CreateProcessInfo.lpBaseOfImage > 0xFFFFFFFFULL;
        size_t ptrSize = is64bitModule ? 8 : arch->pointerSize();
        ReadProcessMemory(pi.hProcess, ev.u.CreateProcessInfo.lpImageName, &namePtr, ptrSize, NULL);
        
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
    stopReason = StopReason::ThreadCreated;
    stopAddress = 0;

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

    stopReason = StopReason::ModuleLoaded;

    // Get DLL name if available
    char dllName[MAX_PATH] = {0};
    if (ev.u.LoadDll.lpImageName) {
        // Read the pointer to the name string.
        // In WOW64 processes, early 64-bit DLLs (ntdll, wow64*.dll) have
        // 64-bit name pointers while 32-bit DLLs have 32-bit ones.
        // Use the module base address to distinguish.
        DWORD64 namePtr = 0;
        bool is64bitModule = (uint64_t)ev.u.LoadDll.lpBaseOfDll > 0xFFFFFFFFULL;
        size_t ptrSize = is64bitModule ? 8 : arch->pointerSize();
        ReadProcessMemory(pi.hProcess, ev.u.LoadDll.lpImageName, &namePtr, ptrSize, NULL);
        
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
        std::stringstream ss;
        ss << "(windows) LOAD_DLL base=0x" << std::hex << (uint64_t)ev.u.LoadDll.lpBaseOfDll;
        if (dllName[0]) {
            ss << " " << dllName;
        }
        log(ss.str());
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
    stopReason = StopReason::ModuleUnloaded;
    
    if (log) {
        std::stringstream ss;
        ss << "(windows) UNLOAD_DLL base=0x" << std::hex << (uint64_t)ev.u.UnloadDll.lpBaseOfDll;
        log(ss.str());
    }
    
    // TODO: Could notify symbol provider to unload module symbols
}

void WindowsBackend::handleOtherDebugEvent(const DEBUG_EVENT &ev) {
    if (log) log("(windows) DEBUG_EVENT code=" + std::to_string(ev.dwDebugEventCode) + " pid=" + std::to_string(ev.dwProcessId) + " tid=" + std::to_string(ev.dwThreadId));
}

// isAttached() and attachedPid() are implemented inline in the header

} // namespace smalldbg
