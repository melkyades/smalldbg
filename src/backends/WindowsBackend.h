#pragma once

#include "Backend.h"
#include <vector>
#include <cstdint>
#include <windows.h>
#include <thread>
#include <mutex>
#include <unordered_map>

namespace smalldbg {

class WindowsBackend : public Backend {
public:
    WindowsBackend(Debugger* dbg, Mode m, Arch a);
    ~WindowsBackend() override;

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
    // process/thread handles and debug loop
    PROCESS_INFORMATION pi{};
    std::thread debugThread;
    bool attached{false};
    std::string launchPath; // Used to pass launch command to debug thread
    bool running{false}; // Protected by stopMutex
    std::vector<uint8_t> memory;
    Registers regs{};
    std::vector<Breakpoint> bps;
    
    // stop state - all protected by stopMutex
    std::mutex stopMutex;
    std::condition_variable stopCV;
    bool stopped{false};
    StopReason stopReason{StopReason::None};
    Address stopAddress{0};
    DWORD stopThreadId{0};
    bool continueRequested{false};
    
    // Process attach/launch synchronization
    HANDLE processAttachSem{NULL};

    std::mutex bpMutex;
    std::unordered_map<Address, uint8_t> bpOriginal;
    // map thread id -> address to reinsert breakpoint after single-step
    std::unordered_map<DWORD, Address> pendingReinsert;

    // debug loop
    void debugLoop();
    bool createProcessForDebug();
    Status waitForProcessAttach();
    bool handleExceptionEvent(const DEBUG_EVENT &ev);
    bool handleBreakpointEvent(const DEBUG_EVENT &ev, uintptr_t addr);
    bool handleSingleStepEvent(const DEBUG_EVENT &ev);
    bool handleCreateProcessEvent(const DEBUG_EVENT &ev);
    void handleThreadCreatedEvent(const DEBUG_EVENT &ev);
    void handleExitProcessEvent(const DEBUG_EVENT &ev);
    void handleOtherDebugEvent(const DEBUG_EVENT &ev);
    bool captureThreadContext(DWORD tid, CONTEXT &ctx) const;
    Status contextToRegisters(const CONTEXT &ctx, Registers &out) const;
    
    // Helper to execute code under stopMutex protection
    template<typename Func>
    void withStopLock(Func&& func) {
        std::lock_guard<std::mutex> lock(stopMutex);
        func();
    }

    bool isAttached() const override { return attached; }
    std::optional<int> attachedPid() const override { if (attached) return static_cast<int>(pi.dwProcessId); return std::nullopt; }
    std::shared_ptr<Process> getProcess() const override { return process; }

private:
    std::shared_ptr<Process> process;
};

} // namespace smalldbg
