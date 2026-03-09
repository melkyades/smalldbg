// PtraceBackend — common (platform-independent) debugger backend logic.
//
// Platform-specific operations (memory, registers, threads, modules) are
// delegated to PtracePlatform, with implementations in:
//   - PtracePlatformMac.cpp  (macOS / Mach APIs)
//   - PtracePlatformLinux.cpp (Linux / /proc + ptrace)

#include "PtraceBackend.h"
#include "PtracePlatform.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/SymbolProvider.h"
#include "../symbols/DwarfBackend.h"
#include <cstring>
#include <algorithm>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

namespace smalldbg {

// ---------------------------------------------------------------------------
// Architecture-specific constants (same on macOS and Linux)
// ---------------------------------------------------------------------------

#if defined(__arm64__) || defined(__aarch64__)
static const uint8_t kBpInstr[] = {0x00, 0x00, 0x20, 0xD4}; // BRK #0
#else // x86_64
static const uint8_t kBpInstr[] = {0xCC}; // INT 3
#endif
static constexpr size_t kBpSize = sizeof(kBpInstr);

size_t PtraceBackend::breakpointSize() const {
    return kBpSize;
}

Address PtraceBackend::adjustPcAfterBreakpoint(Address pc) const {
#if defined(__arm64__) || defined(__aarch64__)
    return pc;        // ARM64: PC points TO the BRK instruction
#else
    return pc - 1;    // x86_64: PC points PAST the INT 3
#endif
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

PtraceBackend::PtraceBackend(Debugger* dbg, Mode m, const Arch* a)
    : Backend(dbg, m, a)
    , platform(PtracePlatform::create()) {
    platform->setLogPtr(&log);
}

PtraceBackend::~PtraceBackend() {
    if (attached)
        detach();
}

// ---------------------------------------------------------------------------
// Thread enumeration
// ---------------------------------------------------------------------------

void PtraceBackend::enumerateAndRegisterThreads() {
    auto threads = platform->enumerateThreads();
    for (auto tid : threads) {
        if (!process->getThread(tid))
            process->registerThread(tid);
    }
}

// ---------------------------------------------------------------------------
// launch
// ---------------------------------------------------------------------------

Status PtraceBackend::launch(const std::string &path, const std::vector<std::string> &args) {
    if (attached) return Status::AlreadyAttached;

    pid_t child = fork();
    if (child < 0) {
        if (log) log("(ptrace) fork failed: " + std::string(strerror(errno)));
        return Status::Error;
    }

    if (child == 0) {
        // --- child process ---
        platform->ptraceTraceMe();

        std::vector<const char*> argv;
        argv.push_back(path.c_str());
        for (auto& a : args) argv.push_back(a.c_str());
        argv.push_back(nullptr);

        execvp(path.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    // --- parent process ---
    targetPid = child;

    // Child stops at exec (SIGTRAP) due to trace-me
    int status = 0;
    if (waitpid(targetPid, &status, 0) < 0 || !WIFSTOPPED(status)) {
        if (log) log("(ptrace) child did not stop after launch");
        kill(targetPid, SIGKILL);
        waitpid(targetPid, nullptr, 0);
        return Status::Error;
    }

    // Acquire platform-specific process handle
    if (platform->acquireProcess(targetPid) != Status::Ok) {
        platform->ptraceKill(targetPid);
        waitpid(targetPid, nullptr, 0);
        return Status::Error;
    }

    attached = true;

    // Build Process / Thread objects
    initProcess(static_cast<uintptr_t>(targetPid));
    enumerateAndRegisterThreads();

    // Initial stop state
    stopped = true;
    stopReason = StopReason::ProcessCreated;
    stopAddress = 0;
    selectPrimaryThread();

    // Register the DWARF symbol backend
    auto dwarf = std::make_unique<DwarfBackend>(this);
    debugger->getSymbolProvider()->addBackend(std::move(dwarf));

    if (log) log("(ptrace) launched " + path + " (pid=" + std::to_string(targetPid) + ")");
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// attach
// ---------------------------------------------------------------------------

Status PtraceBackend::attach(uintptr_t pid) {
    if (attached) return Status::AlreadyAttached;

    targetPid = static_cast<int>(pid);

    if (platform->ptraceAttach(targetPid) < 0) {
        targetPid = -1;
        return Status::Error;
    }

    // Wait for the SIGSTOP that attach delivers
    int status = 0;
    if (waitpid(targetPid, &status, 0) < 0 || !WIFSTOPPED(status)) {
        if (log) log("(ptrace) child did not stop after attach");
        platform->ptraceDetach(targetPid);
        targetPid = -1;
        return Status::Error;
    }

    if (platform->acquireProcess(targetPid) != Status::Ok) {
        platform->ptraceDetach(targetPid);
        targetPid = -1;
        return Status::Error;
    }

    attached = true;
    initProcess(static_cast<uintptr_t>(targetPid));
    enumerateAndRegisterThreads();

    stopped = true;
    stopReason = StopReason::InitialBreakpoint;
    stopAddress = 0;
    selectPrimaryThread();

    auto dwarf = std::make_unique<DwarfBackend>(this);
    debugger->getSymbolProvider()->addBackend(std::move(dwarf));

    if (log) log("(ptrace) attached to pid " + std::to_string(pid));
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// detach
// ---------------------------------------------------------------------------

Status PtraceBackend::detach() {
    if (!attached) return Status::NotAttached;

    // Clear all breakpoints (restore original bytes)
    for (auto& bp : bps) {
        auto it = bpOriginalBytes.find(bp.addr);
        if (it != bpOriginalBytes.end())
            writeMemory(bp.addr, it->second.data(), it->second.size());
    }
    bps.clear();
    bpOriginalBytes.clear();
    pendingReinsert.clear();

    platform->ptraceDetach(targetPid);
    platform->releaseProcess();

    if (log) log("(ptrace) detached from pid " + std::to_string(targetPid));

    attached = false;
    targetPid = -1;
    stopped = false;
    stopReason = StopReason::None;
    stopAddress = 0;
    process.reset();
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// resume / step / suspend
// ---------------------------------------------------------------------------

Status PtraceBackend::resume() {
    if (!attached) return Status::NotAttached;

    // If there's a pending breakpoint re-insert, single-step first then continue
    if (!pendingReinsert.empty()) {
        if (platform->ptraceStep(targetPid) < 0) return Status::Error;

        int status = 0;
        waitpid(targetPid, &status, 0);
        handlePendingReinsert();
    }

    if (platform->ptraceContinue(targetPid) < 0) return Status::Error;

    stopped = false;
    stopReason = StopReason::None;
    if (log) log("(ptrace) resume");
    return Status::Ok;
}

Status PtraceBackend::step(Thread* /*thread*/) {
    if (!attached) return Status::NotAttached;

    // Handle pending breakpoint re-insertion before stepping
    if (!pendingReinsert.empty()) {
        if (platform->ptraceStep(targetPid) < 0) return Status::Error;

        int status = 0;
        waitpid(targetPid, &status, 0);
        handlePendingReinsert();
    }

    if (platform->ptraceStep(targetPid) < 0) return Status::Error;

    stopped = false;
    stopReason = StopReason::None;
    if (log) log("(ptrace) step");
    return Status::Ok;
}

Status PtraceBackend::suspend() {
    if (!attached) return Status::NotAttached;

    if (kill(targetPid, SIGSTOP) < 0) {
        if (log) log("(ptrace) kill(SIGSTOP) failed: " + std::string(strerror(errno)));
        return Status::Error;
    }

    if (log) log("(ptrace) suspend requested");
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------

Status PtraceBackend::setBreakpoint(Address addr, const std::string &name) {
    if (!attached) return Status::NotAttached;
    if (bpOriginalBytes.find(addr) != bpOriginalBytes.end()) return Status::Error;

    // Save original bytes
    std::vector<uint8_t> original(kBpSize);
    if (readMemory(addr, original.data(), kBpSize) != Status::Ok) return Status::Error;

    // Write breakpoint instruction
    if (writeMemory(addr, kBpInstr, kBpSize) != Status::Ok) return Status::Error;

    bpOriginalBytes[addr] = std::move(original);
    Breakpoint bp;
    bp.addr = addr;
    bp.enabled = true;
    bp.name = name;
    bps.push_back(bp);

    if (log) log("(ptrace) breakpoint set at 0x" + std::to_string(addr));
    return Status::Ok;
}

Status PtraceBackend::clearBreakpoint(Address addr) {
    if (!attached) return Status::NotAttached;

    auto it = bpOriginalBytes.find(addr);
    if (it == bpOriginalBytes.end()) return Status::NotFound;

    // Restore original bytes
    if (writeMemory(addr, it->second.data(), it->second.size()) != Status::Ok) return Status::Error;
    bpOriginalBytes.erase(it);

    auto pred = [&](const Breakpoint& b) { return b.addr == addr; };
    bps.erase(std::remove_if(bps.begin(), bps.end(), pred), bps.end());

    if (log) log("(ptrace) breakpoint cleared at 0x" + std::to_string(addr));
    return Status::Ok;
}

std::vector<Breakpoint> PtraceBackend::listBreakpoints() const {
    return bps;
}

// ---------------------------------------------------------------------------
// Memory access — delegate to platform
// ---------------------------------------------------------------------------

Status PtraceBackend::readMemory(Address address, void *outBuf, size_t size) const {
    if (!attached) return Status::NotAttached;
    return platform->readMemory(address, outBuf, size);
}

Status PtraceBackend::writeMemory(Address address, const void *data, size_t size) {
    if (!attached) return Status::NotAttached;
    return platform->writeMemory(address, data, size);
}

// ---------------------------------------------------------------------------
// Register access — delegate to platform
// ---------------------------------------------------------------------------

Status PtraceBackend::getRegisters(Thread* thread, Registers &out) const {
    if (!attached) return Status::NotAttached;
    if (!thread) return Status::NotFound;

    std::memset(&out, 0, sizeof(out));
    out.arch = arch;
    return platform->getThreadRegisters(thread->getThreadId(), arch, out);
}

// ---------------------------------------------------------------------------
// Caller register recovery (frame-pointer based unwinding)
// ---------------------------------------------------------------------------

Status PtraceBackend::recoverCallerRegisters(Registers& regs) const {
    Address bp = regs.fp();
    size_t ptrSize = regs.pointerSize();

    Address nextBp = 0;
    Address nextIp = 0;
    if (readMemory(bp, &nextBp, ptrSize) != Status::Ok) return Status::Error;
    if (readMemory(bp + ptrSize, &nextIp, ptrSize) != Status::Ok) return Status::Error;

    if (nextBp == 0 || nextIp == 0) return Status::Error;

    regs.setIp(nextIp);
    regs.setFp(nextBp);
    regs.setSp(bp + 2 * ptrSize);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Module enumeration — delegate to platform
// ---------------------------------------------------------------------------

std::vector<ModuleInfo> PtraceBackend::enumerateModules() const {
    if (!attached) return {};
    return platform->enumerateModules();
}

// ---------------------------------------------------------------------------
// Find breakpoint thread
// ---------------------------------------------------------------------------

ThreadId PtraceBackend::findBreakpointThread() {
    auto threads = platform->enumerateThreads();
    for (auto tid : threads) {
        Registers regs{};
        if (platform->getThreadRegisters(tid, arch, regs) == Status::Ok) {
            Address pc = adjustPcAfterBreakpoint(regs.ip());
            if (bpOriginalBytes.find(pc) != bpOriginalBytes.end())
                return tid;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// waitForChildStop — poll waitpid with optional timeout
// ---------------------------------------------------------------------------

int PtraceBackend::waitForChildStop(int timeout_ms) {
    if (timeout_ms == 0) {
        int status = 0;
        pid_t r = waitpid(targetPid, &status, WNOHANG);
        if (r <= 0) return -1;
        if (WIFEXITED(status) || WIFSIGNALED(status)) return -2;
        if (WIFSTOPPED(status)) return WSTOPSIG(status);
        return -1;
    }

    if (timeout_ms < 0) {
        int status = 0;
        pid_t r = waitpid(targetPid, &status, 0);
        if (r < 0) return -1;
        if (WIFEXITED(status) || WIFSIGNALED(status)) return -2;
        if (WIFSTOPPED(status)) return WSTOPSIG(status);
        return -1;
    }

    // Timed wait: poll with WNOHANG in 50ms intervals
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        int status = 0;
        pid_t r = waitpid(targetPid, &status, WNOHANG);
        if (r > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) return -2;
            if (WIFSTOPPED(status)) return WSTOPSIG(status);
        }
        usleep(50000); // 50ms
        elapsed += 50;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// waitForEvent
// ---------------------------------------------------------------------------

StopReason PtraceBackend::waitForEvent(StopReason reason, int timeout_ms) {
    if (!attached) return StopReason::None;

    // If already stopped and reason matches, return immediately
    if (stopped && (reason == StopReason::None || stopReason == reason))
        return stopReason;

    while (true) {
        int sig = waitForChildStop(timeout_ms);
        if (sig == -1) return StopReason::None;

        if (sig == -2) {
            stopped = true;
            stopReason = StopReason::ProcessExit;
            stopAddress = 0;
            attached = false;
            platform->releaseProcess();
            if (log) log("(ptrace) process exited");
            if (eventCallback) eventCallback(stopReason, stopAddress);
            return stopReason;
        }

        // Re-enumerate threads (new ones may have appeared)
        enumerateAndRegisterThreads();

        if (sig == SIGTRAP) {
            ThreadId bpThread = findBreakpointThread();
            if (bpThread != 0) {
                handleBreakpointHit(bpThread);
            } else {
                // Single-step completion
                stopped = true;
                stopReason = StopReason::SingleStep;
                stopAddress = 0;
                handlePendingReinsert();

                auto thread = debugger->getCurrentThread();
                if (thread) {
                    Registers regs{};
                    if (getRegisters(thread.get(), regs) == Status::Ok)
                        stopAddress = regs.ip();
                }
            }
        } else if (sig == SIGSTOP) {
            stopped = true;
            stopReason = StopReason::Exception;
            stopAddress = 0;
            if (log) log("(ptrace) SIGSTOP received");
            selectPrimaryThread();
        } else {
            stopped = true;
            stopReason = StopReason::Exception;
            stopAddress = 0;
            if (log) log("(ptrace) signal " + std::to_string(sig) + " received");
            selectPrimaryThread();
        }

        if (eventCallback) {
            bool shouldContinue = eventCallback(stopReason, stopAddress);
            if (shouldContinue) {
                platform->ptraceContinue(targetPid);
                stopped = false;
                stopReason = StopReason::None;
                continue;
            }
        }

        if (reason == StopReason::None || stopReason == reason)
            return stopReason;

        // Auto-continue if reason doesn't match
        platform->ptraceContinue(targetPid);
        stopped = false;
        stopReason = StopReason::None;
    }
}

// ---------------------------------------------------------------------------
// Breakpoint hit handling
// ---------------------------------------------------------------------------

void PtraceBackend::selectPrimaryThread() {
    auto primary = process->primaryThread();
    if (!primary) return;
    debugger->setCurrentThread(primary);
    Registers regs{};
    if (getRegisters(primary.get(), regs) == Status::Ok)
        stopAddress = regs.ip();
}

void PtraceBackend::handleBreakpointHit(ThreadId bpThread) {
    auto threadOpt = process->getThread(bpThread);
    if (!threadOpt) return;

    Registers regs{};
    getRegisters(threadOpt->get(), regs);
    Address bpAddr = adjustPcAfterBreakpoint(regs.ip());

    // Restore original bytes so the instruction can execute normally
    auto it = bpOriginalBytes.find(bpAddr);
    if (it != bpOriginalBytes.end())
        writeMemory(bpAddr, it->second.data(), it->second.size());

    // Fix the PC to point to the original instruction
    platform->setThreadPc(bpThread, bpAddr);

    // Record that we need to re-insert after a single-step
    pendingReinsert[bpThread] = bpAddr;

    stopped = true;
    stopReason = StopReason::Breakpoint;
    stopAddress = bpAddr;
    debugger->setCurrentThread(*threadOpt);

    if (log) log("(ptrace) breakpoint hit at 0x" + std::to_string(bpAddr)
                 + " tid=" + std::to_string(bpThread));
}

void PtraceBackend::handlePendingReinsert() {
    for (auto it = pendingReinsert.begin(); it != pendingReinsert.end(); ) {
        Address bpAddr = it->second;
        if (bpOriginalBytes.find(bpAddr) != bpOriginalBytes.end()) {
            writeMemory(bpAddr, kBpInstr, kBpSize);
            if (log) log("(ptrace) re-inserted breakpoint at 0x" + std::to_string(bpAddr));
        }
        it = pendingReinsert.erase(it);
    }
}

} // namespace smalldbg
