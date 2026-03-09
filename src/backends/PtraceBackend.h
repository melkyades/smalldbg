#pragma once

#include "Backend.h"
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <memory>

namespace smalldbg {

class PtracePlatform;

class PtraceBackend : public Backend {
public:
    PtraceBackend(Debugger* dbg, Mode m, const Arch* a);
    ~PtraceBackend() override;

    Status attach(uintptr_t pid) override;
    Status launch(const std::string &path, const std::vector<std::string> &args) override;
    Status detach() override;

    Status resume() override;
    Status step(Thread* thread) override;
    Status suspend() override;

    Status setBreakpoint(Address addr, const std::string &name) override;
    Status clearBreakpoint(Address addr) override;
    std::vector<Breakpoint> listBreakpoints() const override;

    Status readMemory(Address address, void *outBuf, size_t size) const override;
    Status writeMemory(Address address, const void *data, size_t size) override;
    Status getRegisters(Thread* thread, Registers &out) const override;
    Status recoverCallerRegisters(Registers& regs) const override;

    std::vector<ModuleInfo> enumerateModules() const override;
    
    StopReason getStopReason() const override { return stopReason; }
    bool isStopped() const override { return stopped; }
    Address getStopAddress() const override { return stopAddress; }
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1) override;

private:
    std::unique_ptr<PtracePlatform> platform;

    bool attached{false};
    int targetPid{-1};
    bool stopped{false};
    StopReason stopReason{StopReason::None};
    Address stopAddress{0};
    std::vector<Breakpoint> bps;

    // Breakpoint tracking: address -> original bytes that were overwritten
    std::unordered_map<Address, std::vector<uint8_t>> bpOriginalBytes;

    // After hitting a breakpoint, single-step then re-insert.
    // Maps thread ID -> breakpoint address needing re-insertion.
    std::unordered_map<ThreadId, Address> pendingReinsert;

    bool isAttached() const override { return attached; }

    // Enumerate threads from the platform and register them with the Process
    void enumerateAndRegisterThreads();

    // Breakpoint instruction size for the current architecture (1 for x86_64, 4 for ARM64)
    size_t breakpointSize() const;

    // Adjust PC after hitting a software breakpoint
    Address adjustPcAfterBreakpoint(Address pc) const;

    // Wait for the child process to stop via waitpid.
    // Returns the signal number that caused the stop, or -1 on exit/error.
    int waitForChildStop(int timeout_ms);

    // Find the thread whose PC matches a breakpoint address.
    // Returns the ThreadId, or 0 if none found.
    ThreadId findBreakpointThread();

    // Handle a breakpoint hit on the given thread
    void handleBreakpointHit(ThreadId bpThread);

    // Re-insert breakpoint instructions after a single-step over breakpoint
    void handlePendingReinsert();

    // Select the primary thread as the current thread and read its stop address
    void selectPrimaryThread();
};

} // namespace smalldbg
