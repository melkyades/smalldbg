// macOS PtracePlatform — uses Mach APIs for memory, registers, and threads.
#pragma once

#include "../../../backends/PtracePlatform.h"
#include <mach/mach_types.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

namespace smalldbg {

struct MachExceptionMessage;

// One entry of the target's VM map: where it is and what it was allocated as.
struct MapEntry {
    mach_vm_address_t start{0};
    mach_vm_address_t end{0};
    unsigned int tag{0};  // VM_MEMORY_*, what the allocation was made for
};

class PtracePlatformMac : public PtracePlatform {
public:
    ~PtracePlatformMac() override;

    int ptraceTraceMe() override;
    int ptraceAttach(int pid) override;
    int ptraceDetach(int pid) override;
    int ptraceContinue(int pid) override;
    int ptraceStep(int pid, ThreadId thread) override;
    void ptraceKill(int pid) override;

    int spawnStopped(const std::string& path,
                     const std::vector<std::string>& args,
                     const std::string& workingDir) override;

    int waitForStop(int pid, int timeoutMs, int& status) override;
    ThreadId stoppedThread() const override { return lastStopThread; }

    Status acquireProcess(int pid) override;
    void releaseProcess() override;

    Status readMemory(Address addr, void* buf, size_t size) const override;
    Status writeMemory(Address addr, const void* data, size_t size) override;
    std::pair<Address, Address> allocationContaining(Address addr) const override;

    Status getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const override;
    Status setThreadPc(ThreadId tid, Address pc) const override;

    std::vector<ThreadId> enumerateThreads() override;
    std::vector<ModuleInfo> enumerateModules() const override;

    void setWatchpoint(uint64_t addr, uint64_t match, uint64_t mask) override;

private:
    int targetPid{-1};
    mach_port_t taskPort{MACH_PORT_NULL};
    std::vector<mach_port_t> cachedThreadPorts;

    // Read one dyld_image_info entry and append to modules
    void readModuleEntry(std::vector<ModuleInfo>& modules, Address entryAddr) const;
    std::optional<MapEntry> growBackward(MapEntry allocation) const;
    MapEntry growForward(MapEntry allocation) const;
    std::vector<ModuleInfo> modulesMappedByKernel() const;
    void addKernelMappedModule(std::vector<ModuleInfo>& modules, Address address) const;

    // Mach exception server state.
    mach_port_t exceptionPort{MACH_PORT_NULL};
    std::thread exceptionThread;
    std::atomic<bool> exceptionThreadStop{false};
    std::mutex exceptionMutex;
    // Exceptions caught and not yet answered, oldest first.
    struct HeldException {
        mach_port_t replyPort{MACH_PORT_NULL};
        mach_msg_bits_t replyBits{0};
        mach_msg_id_t replyId{0};
        ThreadId thread{0};
        int exception{0};   // EXC_*
        int64_t code{0};
        int64_t subcode{0};
        bool reported{false};  // waitForStop has answered it
    };
    std::deque<HeldException> held;
    std::condition_variable exceptionCv;
    ThreadId lastStopThread{0};
    // Threads whose fault was answered by letting the kernel raise its
    // signal: that signal is the program's to handle, not another stop.
    std::set<ThreadId> deliverNextSignal;

    // The thread being stepped, and the others kept suspended meanwhile.
    ThreadId steppingThread{0};
    std::vector<mach_port_t> keptSuspended;

    Status startExceptionServer();
    void stopExceptionServer();
    void exceptionServerLoop();
    void receiveException(const MachExceptionMessage& msg);
    bool passesThrough(const HeldException& exception);
    void hold(const HeldException& exception);
    int takeStop();
    void keepSuspendedUnless(mach_port_t thread, mach_port_t stepped);
    void finishStep();
    void resumeHeld();
    void answer(const HeldException& exception, kern_return_t result);
    void logFault(const MachExceptionMessage& msg) const;
    bool handleWatchpointException(const HeldException& exception);
    void logWatchpointHit(mach_port_t thread);

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
