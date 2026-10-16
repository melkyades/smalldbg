// PtraceBackend — common (platform-independent) debugger backend logic.
//
// Platform-specific operations (memory, registers, threads, modules) are
// delegated to PtracePlatform, with implementations in:
//   - PtracePlatformMac.cpp  (macOS / Mach APIs)
//   - PtracePlatformLinux.cpp (Linux / /proc + ptrace)

#include "PtraceBackend.h"
#include "PtracePlatform.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/NativeUnwinder.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"
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

// How long a suspend waits for the target to halt.
static constexpr int kSuspendTimeoutMs = 5000;

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

Status PtraceBackend::launch(const std::string &path, const std::vector<std::string> &args,
                             const std::string &workingDir) {
    if (attached) return Status::AlreadyAttached;

    int child = platform->spawnStopped(path, args, workingDir);
    if (child < 0) return Status::Error;

    targetPid = child;

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
    selectStoppedThread();

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

    if (platform->attachStopped(targetPid) < 0) {
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
    selectStoppedThread();

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
    if (stepPastBreakpoint() != Status::Ok) return Status::Error;

    if (platform->ptraceContinue(targetPid) < 0) return Status::Error;

    stopped = false;
    stopReason = StopReason::None;
    if (log) log("(ptrace) resume");
    return Status::Ok;
}

Status PtraceBackend::step(Thread* thread) {
    if (!attached) return Status::NotAttached;
    if (!thread) thread = debugger->getCurrentThread().get();
    if (!thread) return Status::NotFound;

    // A thread stopped on a breakpoint has already stepped off it.
    bool onBreakpoint = pendingReinsert.count(thread->getThreadId()) > 0;
    if (stepPastBreakpoint() != Status::Ok) return Status::Error;
    if (onBreakpoint) return completeStep();

    if (platform->ptraceStep(targetPid, thread->getThreadId()) < 0) return Status::Error;

    stopped = false;
    stopReason = StopReason::None;
    if (log) log("(ptrace) step");
    return Status::Ok;
}

// Steps the thread that stopped on a breakpoint over the instruction the
// breakpoint replaced, and puts the breakpoint back.
Status PtraceBackend::stepPastBreakpoint() {
    if (pendingReinsert.empty()) return Status::Ok;
    ThreadId thread = pendingReinsert.begin()->first;
    if (platform->ptraceStep(targetPid, thread) < 0) return Status::Error;

    int status = 0;
    platform->waitForStop(targetPid, -1, status);
    handlePendingReinsert();
    return Status::Ok;
}

// Reports a step that is already done, as the stop that ends it.
Status PtraceBackend::completeStep() {
    stopped = true;
    stopReason = StopReason::SingleStep;
    selectStoppedThread();
    if (log) log("(ptrace) step");
    return Status::Ok;
}

void PtraceBackend::noticeStop() {
    if (attached && !stopped) waitForEvent(StopReason::None, 0);
}

// Returns once the target has halted, so the caller never reads threads and
// frames off a running process.
Status PtraceBackend::suspend() {
    if (!attached) return Status::NotAttached;
    if (stopped) return Status::Ok;

    if (platform->interrupt(targetPid) < 0) {
        if (log) log("(ptrace) interrupt failed: " + std::string(strerror(errno)));
        return Status::Error;
    }
    if (log) log("(ptrace) suspend requested");
    if (waitForEvent(StopReason::None, kSuspendTimeoutMs) == StopReason::None) {
        if (log) log("(ptrace) suspend: target did not halt");
        return Status::Error;
    }
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------

Status PtraceBackend::setWatchpoint(Address addr, uint64_t match, uint64_t mask) {
    platform->setWatchpoint(addr, match, mask);
    return Status::Ok;
}

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

std::pair<Address, Address> PtraceBackend::allocationContaining(Address address) const {
    if (!attached) return {0, 0};
    return platform->allocationContaining(address);
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

namespace {

// Native frames, unwound by the platform's call frame information where it
// has some, and by the frame pointer chain otherwise: code built without
// frame pointers, such as x86-64 code at -O2, breaks that chain.
class PtraceUnwinder : public NativeUnwinder {
public:
    explicit PtraceUnwinder(const PtracePlatform& p) : platform(p) {}

    Status unwind(StackFrame& frame, Debugger* debugger) override {
        if (platform.recoverCallerFromFrameInfo(frame.registers, frame.allRegisters))
            return Status::Ok;
        return NativeUnwinder::unwind(frame, debugger);
    }

private:
    const PtracePlatform& platform;
};

} // namespace

std::unique_ptr<StackUnwinder> PtraceBackend::createUnwinder() const {
    return std::make_unique<PtraceUnwinder>(*platform);
}

Status PtraceBackend::recoverCallerRegisters(Registers& regs) const {
    Address bp = regs.fp();
    size_t ptrSize = regs.pointerSize();

    Address nextBp = 0;
    Address nextIp = 0;
    if (readMemory(bp, &nextBp, ptrSize) != Status::Ok) return Status::Error;
    if (readMemory(bp + ptrSize, &nextIp, ptrSize) != Status::Ok) return Status::Error;

    if (nextBp == 0 || nextIp == 0) return Status::Error;

    regs.setIp(platform->codeAddress(nextIp));
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
    ThreadId stoppedThread = platform->stoppedThread();
    if (stoppedThread != 0)
        return isAtBreakpoint(stoppedThread) ? stoppedThread : 0;

    for (auto tid : platform->enumerateThreads())
        if (isAtBreakpoint(tid)) return tid;
    return 0;
}

bool PtraceBackend::isAtBreakpoint(ThreadId thread) const {
    Registers regs{};
    if (platform->getThreadRegisters(thread, arch, regs) != Status::Ok) return false;
    Address pc = adjustPcAfterBreakpoint(regs.ip());
    return bpOriginalBytes.find(pc) != bpOriginalBytes.end();
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
        int sig = platform->waitForStop(targetPid, timeout_ms, lastChildStatus);
        if (sig == -1) return StopReason::None;

        if (sig == -2) {
            stopped = true;
            stopReason = StopReason::ProcessExit;
            stopAddress = 0;
            attached = false;
            platform->releaseProcess();
            if (log) {
                std::string msg = "(ptrace) process exited";
                if (lastChildStatus != 0) {
                    if (WIFSIGNALED(lastChildStatus))
                        msg += " (killed by signal " +
                               std::to_string(WTERMSIG(lastChildStatus)) + ")";
                    else if (WIFEXITED(lastChildStatus))
                        msg += " (exit code " +
                               std::to_string(WEXITSTATUS(lastChildStatus)) + ")";
                }
                log(msg);
            }
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
                selectStoppedThread();
            }
        } else if (sig == SIGSTOP) {
            stopped = true;
            stopReason = StopReason::Exception;
            stopAddress = 0;
            if (log) log("(ptrace) SIGSTOP received");
            selectStoppedThread();
        } else {
            stopped = true;
            stopReason = StopReason::Exception;
            stopAddress = 0;
            if (log) log("(ptrace) signal " + std::to_string(sig) + " received");
            selectStoppedThread();
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

// Makes the thread the platform says stopped the current one or, when it
// cannot tell, the thread the process started on, which under ptrace has the
// process's own id; when neither is known the current thread stays.
void PtraceBackend::selectStoppedThread() {
    ThreadId stoppedThread = platform->stoppedThread();
    if (stoppedThread == 0) stoppedThread = static_cast<ThreadId>(process->getPid());
    auto thread = process->getThread(stoppedThread);
    if (thread) debugger->setCurrentThread(*thread);

    auto current = debugger->getCurrentThread();
    Registers regs{};
    if (current && getRegisters(current.get(), regs) == Status::Ok)
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
