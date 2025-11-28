#pragma once

#include "Backend.h"
#include <vector>
#include <cstdint>
#include <windows.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace smalldbg {

class WindowsBackend : public Backend {
public:
    WindowsBackend(Mode m, Arch a);
    ~WindowsBackend() override;

    Status attach(int pid) override;
    Status launch(const std::string &path, const std::vector<std::string> &args) override;
    Status detach() override;

    Status resume() override;
    Status step() override;

    Status setBreakpoint(Address addr, const std::string &name) override;
    Status clearBreakpoint(Address addr) override;
    std::vector<Breakpoint> listBreakpoints() const override;

    Status readMemory(Address address, void *outBuf, size_t size) const override;
    Status writeMemory(Address address, const void *data, size_t size) override;
    Status getRegisters(Registers &out) const override;

private:
    // process/thread handles and debug loop
    HANDLE processHandle{NULL};
    PROCESS_INFORMATION pi{};
    std::thread debugThread;
    std::atomic<bool> running{false};
    bool attached{false};
    int pid{-1};
    std::vector<uint8_t> memory;
    Registers regs{};
    std::vector<Breakpoint> bps;

    std::mutex bpMutex;
    std::unordered_map<Address, uint8_t> bpOriginal;
    // map thread id -> address to reinsert breakpoint after single-step
    std::unordered_map<DWORD, Address> pendingReinsert;

    // debug loop
    void debugLoop();
    void handleExceptionEvent(const DEBUG_EVENT &ev);
    void handleBreakpointEvent(const DEBUG_EVENT &ev, uintptr_t addr);
    void handleSingleStepEvent(const DEBUG_EVENT &ev);
    void handleCreateProcessEvent(const DEBUG_EVENT &ev);
    void handleExitProcessEvent(const DEBUG_EVENT &ev);
    void handleOtherDebugEvent(const DEBUG_EVENT &ev);

    bool isAttached() const override { return attached; }
    std::optional<int> attachedPid() const override { if (attached) return pid; return std::nullopt; }
};

} // namespace smalldbg
