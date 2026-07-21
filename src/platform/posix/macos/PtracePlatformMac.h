// macOS PtracePlatform — uses Mach APIs for memory, registers, and threads.
#pragma once

#include "../../../backends/PtracePlatform.h"
#include <mach/mach_types.h>
#include <atomic>
#include <mutex>
#include <set>
#include <thread>

namespace smalldbg {

class PtracePlatformMac : public PtracePlatform {
public:
    ~PtracePlatformMac() override;

    int ptraceTraceMe() override;
    int ptraceAttach(int pid) override;
    int ptraceDetach(int pid) override;
    int ptraceContinue(int pid) override;
    int ptraceStep(int pid) override;
    void ptraceKill(int pid) override;

    int spawnStopped(const std::string& path,
                     const std::vector<std::string>& args) override;

    Status acquireProcess(int pid) override;
    void releaseProcess() override;

    Status readMemory(Address addr, void* buf, size_t size) const override;
    Status writeMemory(Address addr, const void* data, size_t size) override;

    Status getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const override;
    Status setThreadPc(ThreadId tid, Address pc) const override;

    std::vector<ThreadId> enumerateThreads() override;
    std::vector<ModuleInfo> enumerateModules() const override;

    // Surface Mach-caught exceptions to the backend's wait loop so they
    // become normal Exception stops the rest of the debugger understands.
    AsyncException pollAsyncException() override;
    void setWatchpoint(uint64_t addr, uint64_t match, uint64_t mask) override;

    // Mach exception server interface — see PtracePlatformMac.cpp.
    // After acquireProcess() succeeds, callers (the PtraceBackend wait loop)
    // can poll for fatal mach exceptions that bypass the normal waitpid
    // mechanism on macOS (EXC_BAD_ACCESS / EXC_BAD_INSTRUCTION /
    // EXC_ARITHMETIC / EXC_CRASH / EXC_GUARD).  Without this, an assert()
    // or null-deref in the child terminates the process before the debugger
    // ever sees it.
    struct PendingException {
        bool present{false};
        int exception{0};       // EXC_*
        long code{0};           // first element of code array
        long subcode{0};        // second element (often the faulting address)
        ThreadId thread{0};     // offending mach thread port
    };
    PendingException takePendingException();

private:
    int targetPid{-1};
    mach_port_t taskPort{MACH_PORT_NULL};
    std::vector<mach_port_t> cachedThreadPorts;

    // Read one dyld_image_info entry and append to modules
    void readModuleEntry(std::vector<ModuleInfo>& modules, Address entryAddr) const;

    // Mach exception server state.
    mach_port_t exceptionPort{MACH_PORT_NULL};
    std::thread exceptionThread;
    std::atomic<bool> exceptionThreadStop{false};
    std::mutex exceptionMutex;
    PendingException pending_;

    Status startExceptionServer();
    void stopExceptionServer();
    void exceptionServerLoop();

    // HW watchpoint helpers (ARM64). installWatchpointAllThreads sets a
    // write watchpoint on `addr` (must be 8-byte aligned) on every
    // currently-running thread. The watch covers a single 8-byte word.
    // Set match=0 for "log every hit, never stop"; non-zero to break
    // when the post-write value at addr equals match.
    // Pass addr=0 to clear an existing watchpoint.
    void installWatchpointAllThreads(uint64_t addr);
    void installWatchpointOnThread(mach_port_t thread, uint64_t addr);

private:
    // Runtime-settable equivalents of the SMALLDBG_WATCH_* env vars (so a
    // caller can arm/disarm watchpoints after the child has started).
    // Default-initialized from those env vars at startup.
    uint64_t watchAddrLive_{0};
    uint64_t watchMatchLive_{0};
    uint64_t watchMaskLive_{0xFFFFFFFFFFFFFFFFULL};

    // Threads currently in "single-step over the trapping store" state
    // after a watchpoint hit. When a step exception fires on a thread in
    // this set, the handler knows it's the step completion (not a real
    // watchpoint hit) and re-arms the watchpoint.
    std::set<mach_port_t> steppingThreads_;
};

} // namespace smalldbg
