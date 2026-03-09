#pragma once

#include "Backend.h"
#include <vector>
#include <cstdint>
#include <windows.h>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <memory>

namespace smalldbg {

class DbgHelpBackend;

class WindowsBackend : public Backend {
public:
    WindowsBackend(Debugger* dbg, Mode m, const Arch* a);
    ~WindowsBackend() override;

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
    Status getNativeRegisters(Thread* thread, Registers &out) const;
    Status recoverCallerRegisters(Registers& regs) const override;
    
    StopReason getStopReason() const override { return stopReason; }
    bool isStopped() const override { return stopped; }
    Address getStopAddress() const override { return stopAddress; }
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1) override;
    
    // Platform-specific: Get process handle for DbgHelp
    HANDLE getProcessHandle() const { return pi.hProcess; }
    
    // Get the DbgHelp backend (for module loading notifications)
    DbgHelpBackend* getDbgHelpBackend() const { return dbgHelpBackend; }

private:
    // process/thread handles and debug loop
    PROCESS_INFORMATION pi{};
    std::thread debugThread;
    bool attached{false};
    std::string launchPath; // Used to pass launch command to debug thread
    std::string exePath;    // Full path to the main executable
    bool running{false}; // Protected by stopMutex
    std::vector<uint8_t> memory;
    Registers regs{};
    
    // Symbol backend (owned by SymbolProvider, we just keep a pointer)
    DbgHelpBackend* dbgHelpBackend{nullptr};
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
    
    // Track if we've seen the initial breakpoint
    bool seenInitialBreakpoint{false};

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
    void handleLoadDllEvent(const DEBUG_EVENT &ev);
    void handleUnloadDllEvent(const DEBUG_EVENT &ev);
    void handleOtherDebugEvent(const DEBUG_EVENT &ev);
    // WoW64 means we're a 64-bit debugger (x64/ARM64) debugging a 32-bit x86 target.
    bool isWow64() const;
    bool captureWow64Registers(Thread* thread, Registers &out) const;
    bool captureNativeRegisters(Thread* thread, Registers &out) const;
    Status nativeContextToRegisters(const CONTEXT &ctx, Registers &out) const;
    Status wow64ContextToRegisters(const WOW64_CONTEXT &ctx, Registers &out) const;
    
    // Helper to execute code under stopMutex protection
    template<typename Func>
    void withStopLock(Func&& func) {
        std::lock_guard<std::mutex> lock(stopMutex);
        func();
    }

    // Open a thread, suspend it, call func(hThread), resume and close.
    // Returns false if open or suspend fails, otherwise returns func's result.
    bool withSuspendedThread(DWORD tid, DWORD access, const std::function<bool(HANDLE)>& func) const;

    bool isAttached() const override { return attached; }

private:
};

} // namespace smalldbg
