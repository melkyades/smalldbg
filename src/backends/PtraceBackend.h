#pragma once

#include "Backend.h"
#include <vector>
#include <cstdint>

namespace smalldbg {

class PtraceBackend : public Backend {
public:
    PtraceBackend(Debugger* dbg, Mode m, Arch a);
    ~PtraceBackend() override;

    Status attach(int pid) override;
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
    
    StopReason getStopReason() const override { return stopReason; }
    bool isStopped() const override { return stopped; }
    Address getStopAddress() const override { return stopAddress; }
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1) override;

private:
    bool attached{false};
    int targetPid{-1};
    bool stopped{false};
    StopReason stopReason{StopReason::None};
    Address stopAddress{0};
    std::vector<Breakpoint> bps;

    bool isAttached() const override { return attached; }
    std::optional<int> attachedPid() const override { 
        if (attached) return targetPid; 
        return std::nullopt; 
    }
    std::shared_ptr<Process> getProcess() const override { return process; }

private:
    std::shared_ptr<Process> process;
};

} // namespace smalldbg
