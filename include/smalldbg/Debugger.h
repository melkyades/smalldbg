// SmallDBG — minimal public debugger API (header)
#pragma once

#include "Types.h"
#include "SymbolProvider.h"  // Need full definition for SymbolOptions default parameter
#include <functional>
#include <vector>
#include <optional>
#include <memory>

namespace smalldbg {

class Backend;
class Process;
class Thread;
class Unwinder;

class Debugger {
public:
    explicit Debugger(Mode m, Arch arch = Arch::X64);
    ~Debugger();

    // attach/launch lifecycle
    Status attach(int pid);
    Status launch(const std::string &path, const std::vector<std::string> &args = {});
    Status detach();

    // run control
    Status resume();
    Status step();
    Status suspend(); // Interrupt/break into running process
    
    // state queries
    StopReason getStopReason() const;
    bool isStopped() const;
    Address getStopAddress() const;
    
    // Wait for debugger to stop with a specific reason (or any reason if None)
    // Returns the actual stop reason, or None if timeout/error
    // timeout_ms: 0 = no wait, -1 = infinite, >0 = timeout in milliseconds
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1);

    // breakpoints
    Status setBreakpoint(Address addr, const std::string &name = {});
    Status clearBreakpoint(Address addr);
    std::vector<Breakpoint> listBreakpoints() const;

    // helpers
    bool isAttached() const;
    std::optional<int> attachedPid() const;

    // Process/Thread abstraction
    std::shared_ptr<Process> getProcess();
    std::shared_ptr<Thread> getCurrentThread();
    void setCurrentThread(std::shared_ptr<Thread> thread);
    
    // accessors provided by the backend implementation
    Status readMemory(Address address, void *outBuf, size_t size) const;
    Status writeMemory(Address address, const void *data, size_t size);
    Status getRegisters(Registers &out) const;
    Status getRegisters(const Thread* thread, Registers &out) const;
    Status recoverCallerRegisters(Registers& regs) const;

    // Logging callback (simple) — optional
    void setLogCallback(std::function<void(const std::string &)> cb);
    
    // Event callback — called when debugger stops
    // Callback receives (reason, address) - address is relevant for breakpoints/exceptions
    void setEventCallback(std::function<void(StopReason, Address)> cb);

    // Symbol support
    SymbolProvider* getSymbolProvider();
    Status setSymbolOptions(const SymbolOptions& options);  // Set options before process creation
    
    // Unwinder registration
    void registerUnwinder(std::unique_ptr<Unwinder> unwinder);
    const std::vector<std::unique_ptr<Unwinder>>& getUnwinders() const { return unwinders; }
    
    Backend* getBackend() const { return backend; }

private:
    Backend *backend; // pointer to backend implementation
    std::shared_ptr<Thread> selectedThread; // current thread
    std::unique_ptr<SymbolProvider> symbolProvider; // symbol resolution
    std::vector<std::unique_ptr<Unwinder>> unwinders; // registered unwinders (checked in order)
};

} // namespace smalldbg
