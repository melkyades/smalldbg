#include "WindowsBackend.h"
#include <algorithm>
#include <cstring>
#include <windows.h>
#include <TlHelp32.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace smalldbg {

WindowsBackend::WindowsBackend(Mode m, Arch a) : Backend(m,a) {}
WindowsBackend::~WindowsBackend() {
    // ensure debug thread is stopped and handles closed
    running = false;
    if (debugThread.joinable()) debugThread.join();
    if (processHandle) { CloseHandle(processHandle); processHandle = NULL; }
    if (pi.hProcess) { CloseHandle(pi.hProcess); pi.hProcess = NULL; }
    if (pi.hThread) { CloseHandle(pi.hThread); pi.hThread = NULL; }
}

Status WindowsBackend::attach(int p) {
    if (attached) return Status::AlreadyAttached;

    // Attach using the Windows Debug API
    if (!DebugActiveProcess(p)) {
        return Status::Error;
    }
    processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, p);
    if (!processHandle) {
        DebugActiveProcessStop(p);
        return Status::Error;
    }

    pid = p;
    attached = true;
    memory.assign(64*1024, 0);
    regs = Registers{};
    running = true;
    debugThread = std::thread(&WindowsBackend::debugLoop, this);
    if (log) log("(windows) attached to pid " + std::to_string(pid));
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

    // Create process in debug mode so this process becomes the debugger
    if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr, FALSE, DEBUG_PROCESS, nullptr, nullptr, &si, &localPi)) {
        return Status::Error;
    }

    pi = localPi;
    processHandle = pi.hProcess;
    pid = static_cast<int>(pi.dwProcessId);
    attached = true;
    memory.assign(64*1024, 0);
    regs = Registers{};

    running = true;
    debugThread = std::thread(&WindowsBackend::debugLoop, this);
    if (log) log("(windows) launched " + path + " (pid=" + std::to_string(pid) + ")");
    return Status::Ok;
}

Status WindowsBackend::detach() {
    if (!attached) return Status::NotAttached;
    // stop debug loop
    running = false;

    // If we attached to an existing process, call DebugActiveProcessStop
    if (pid > 0) DebugActiveProcessStop(static_cast<DWORD>(pid));

    if (debugThread.joinable()) debugThread.join();

    if (processHandle) { CloseHandle(processHandle); processHandle = NULL; }
    if (pi.hProcess) { CloseHandle(pi.hProcess); pi.hProcess = NULL; }
    if (pi.hThread) { CloseHandle(pi.hThread); pi.hThread = NULL; }

    if (log) log(std::string("(windows) detached from pid ") + std::to_string(pid));
    attached = false;
    pid = -1;
    {
        std::lock_guard<std::mutex> g(bpMutex);
        bpOriginal.clear();
        bps.clear();
    }

    return Status::Ok;
}

Status WindowsBackend::resume() {
    if (!attached) return Status::NotAttached;
    // resume is a no-op from the API point - debug loop continues to process events
    if (log) log("(windows) resume");
    return Status::Ok;
}

Status WindowsBackend::step() {
    if (!attached) return Status::NotAttached;

    // Select a thread from the debuggee and set the trap flag so we get a single-step
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return Status::Error;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD targetTid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == static_cast<DWORD>(pid)) { targetTid = te.th32ThreadID; break; }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    if (!targetTid) return Status::Error;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) return Status::Error;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return Status::Error; }

    // Set trap flag in EFlags/RFlags
    ctx.EFlags |= 0x100;
    if (!SetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return Status::Error; }
    // resume execution
    ResumeThread(hThread);
    CloseHandle(hThread);

    if (log) log("(windows) step requested");
    return Status::Ok;
}

Status WindowsBackend::setBreakpoint(Address addr, const std::string &name) {
    if (!attached) return Status::NotAttached;
    std::lock_guard<std::mutex> g(bpMutex);
    if (bpOriginal.find(addr) != bpOriginal.end()) return Status::Error; // already set

    uint8_t orig = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle, (LPCVOID)addr, &orig, 1, &read) || read!=1) return Status::Error;

    uint8_t int3 = 0xCC;
    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle, (LPVOID)addr, &int3, 1, &written) || written!=1) return Status::Error;
    FlushInstructionCache(processHandle, (LPCVOID)addr, 1);

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
    if (!WriteProcessMemory(processHandle, (LPVOID)addr, &orig, 1, &written) || written != 1) return Status::Error;
    FlushInstructionCache(processHandle, (LPCVOID)addr, 1);
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
    if (!ReadProcessMemory(processHandle, (LPCVOID)address, outBuf, size, &read) || read != size) return Status::NotFound;
    return Status::Ok;
}

Status WindowsBackend::writeMemory(Address address, const void *data, size_t size) {
    if (!attached) return Status::NotAttached;
    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle, (LPVOID)address, data, size, &written) || written != size) return Status::NotFound;
    FlushInstructionCache(processHandle, (LPCVOID)address, size);
    return Status::Ok;
}

Status WindowsBackend::getRegisters(Registers &out) const {
    if (!attached) return Status::NotAttached;

    // Find a thread for the process and grab its context
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return Status::Error;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD targetTid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == static_cast<DWORD>(pid)) { targetTid = te.th32ThreadID; break; }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    if (!targetTid) return Status::Error;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) return Status::Error;

    CONTEXT ctx = {};
    // request appropriate context based on target arch
#ifdef CONTEXT_ALL
    ctx.ContextFlags = CONTEXT_ALL;
#else
    ctx.ContextFlags = CONTEXT_FULL;
#endif
    if (!GetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return Status::Error; }

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
        // FsBase and GsBase are not available in standard CONTEXT structure
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

        // PC and SP aliases
        r.pc = ctx.Rip;
        r.sp = ctx.Rsp;
    } else if (arch == Arch::ARM64) {
        out.arch = Arch::ARM64;
        // ARM64 (Windows CONTEXT.Arm64)
        // Map X0..X28, FP (X29), LR (X30), SP and PC
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
    #else
        // ARM64 context not available on this build -- cannot extract ARM64 regs
        (void)ctx;
    #endif
    }

    CloseHandle(hThread);
    return Status::Ok;
}

void WindowsBackend::debugLoop() {
    DEBUG_EVENT ev;
    while (running) {
        if (!WaitForDebugEvent(&ev, 500)) {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT) continue;
            break;
        }

        switch (ev.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            handleExceptionEvent(ev);
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            handleCreateProcessEvent(ev);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            handleExitProcessEvent(ev);
            break;
        default:
            handleOtherDebugEvent(ev);
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
}

void WindowsBackend::handleExceptionEvent(const DEBUG_EVENT &ev) {
    const auto &ex = ev.u.Exception.ExceptionRecord;
    DWORD code = ex.ExceptionCode;
    uintptr_t addr = reinterpret_cast<uintptr_t>(ex.ExceptionAddress);

    if (code == EXCEPTION_BREAKPOINT) {
        handleBreakpointEvent(ev, addr);
    } else if (code == EXCEPTION_SINGLE_STEP) {
        handleSingleStepEvent(ev);
    } else {
        if (log) log(std::string("(windows) EXCEPTION event code=") + std::to_string(code));
    }
}

void WindowsBackend::handleBreakpointEvent(const DEBUG_EVENT &ev, uintptr_t addr) {
    std::lock_guard<std::mutex> g(bpMutex);
    auto it = bpOriginal.find((Address)addr);
    if (it != bpOriginal.end()) {
        // Restore original byte so the instruction can execute normally
        uint8_t orig = it->second;
        SIZE_T written = 0;
        WriteProcessMemory(processHandle, (LPVOID)addr, &orig, 1, &written);
        FlushInstructionCache(processHandle, (LPCVOID)addr, 1);

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
    } else {
        // Not our breakpoint (could be initial breakpoint from CreateProcess in debug mode) - ignore
        if (log) log(std::string("(windows) BREAKPOINT (non-managed) at ") + std::to_string(addr));
    }
}

void WindowsBackend::handleSingleStepEvent(const DEBUG_EVENT &ev) {
    std::lock_guard<std::mutex> g(bpMutex);
    auto it = pendingReinsert.find(ev.dwThreadId);
    if (it != pendingReinsert.end()) {
        Address baddr = it->second;
        uint8_t int3 = 0xCC;
        SIZE_T written = 0;
        WriteProcessMemory(processHandle, (LPVOID)baddr, &int3, 1, &written);
        FlushInstructionCache(processHandle, (LPCVOID)baddr, 1);
        pendingReinsert.erase(it);
        if (log) log(std::string("(windows) re-inserted INT3 at ") + std::to_string(baddr) + " for tid=" + std::to_string(ev.dwThreadId));
    } else {
        // general single-step event
        if (log) log(std::string("(windows) SINGLE_STEP event pid=") + std::to_string(ev.dwProcessId) + " tid=" + std::to_string(ev.dwThreadId));
    }
}

void WindowsBackend::handleCreateProcessEvent(const DEBUG_EVENT &ev) {
    if (log) log(std::string("(windows) CREATE_PROCESS pid=") + std::to_string(ev.dwProcessId));
}

void WindowsBackend::handleExitProcessEvent(const DEBUG_EVENT &ev) {
    if (log) log(std::string("(windows) EXIT_PROCESS pid=") + std::to_string(ev.dwProcessId));
    running = false;
    attached = false;
}

void WindowsBackend::handleOtherDebugEvent(const DEBUG_EVENT &ev) {
    (void)ev;
    // other events: CREATE_THREAD, EXIT_THREAD, LOAD_DLL, UNLOAD_DLL, OUTPUT_DEBUG_STRING
}

// isAttached() and attachedPid() are implemented inline in the header

} // namespace smalldbg
