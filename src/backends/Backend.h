#pragma once

#include "../../include/smalldbg/Types.h"
#include "../../include/smalldbg/Process.h"
#include <functional>
#include <vector>
#include <optional>
#include <memory>

namespace smalldbg {

struct Breakpoint;
struct Registers;
class Thread;
class Debugger;

class Backend {
public:
    Backend(Debugger* dbg, Mode m, const Arch* a) : debugger(dbg), mode(m), arch(a) {}
    virtual ~Backend() = default;

    virtual Status attach(uintptr_t pid) = 0;
    virtual Status launch(const std::string &path, const std::vector<std::string> &args) = 0;
    virtual Status detach() = 0;

    virtual Status resume() = 0;
    virtual Status step(Thread* thread) = 0;
    virtual Status suspend() = 0; // Interrupt running process

    // --- Reverse debugging (TTD) ---
    // Default implementations return NotSupported; override in backends that support TTD
    virtual Status openTrace(const std::string& tracePath) { (void)tracePath; return Status::NotSupported; }
    virtual Status stepBack(Thread* thread) { (void)thread; return Status::NotSupported; }
    virtual Status reverseResume() { return Status::NotSupported; }
    virtual bool isTTDTrace() const { return false; }

    virtual Status setBreakpoint(Address addr, const std::string &name) = 0;
    virtual Status clearBreakpoint(Address addr) = 0;
    virtual std::vector<Breakpoint> listBreakpoints() const = 0;

    virtual Status readMemory(Address address, void *outBuf, size_t size) const = 0;
    virtual Status writeMemory(Address address, const void *data, size_t size) = 0;
    virtual Status getRegisters(Thread* thread, Registers &out) const = 0;
    
    // Stack unwinding: restore caller's register state from current frame
    // Returns Status::Ok if successful, Status::Error if no unwind info available
    virtual Status recoverCallerRegisters(Registers& regs) const = 0;

    virtual bool isAttached() const { return false; }
    std::optional<uintptr_t> attachedPid() const {
        if (process) return process->getPid();
        return std::nullopt;
    }
    
    virtual StopReason getStopReason() const = 0;
    virtual bool isStopped() const = 0;
    virtual Address getStopAddress() const = 0;
    
    // Wait for debugger to stop with a specific reason (or any reason if None)
    // Returns the actual stop reason, or None if timeout/error
    // timeout_ms: 0 = no wait, -1 = infinite, >0 = timeout in milliseconds
    virtual StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1) = 0;

    void setLogCallback(std::function<void(const std::string &)> cb) { log = std::move(cb); }
    void setEventCallback(std::function<bool(StopReason, Address)> cb) { eventCallback = std::move(cb); }
    
    std::shared_ptr<Process> getProcess() const { return process; }

    // Initialise the process object for this session.
    void initProcess(uintptr_t pid) {
        process = std::make_shared<Process>(debugger, pid);
    }

    // Execute a raw engine command (e.g. "kb", "lm") and return captured output.
    // Only meaningful for engine-based backends (DbgEng); others return empty.
    virtual std::string executeCommand(const std::string& cmd) const { (void)cmd; return {}; }

    // Return information about all loaded modules (executable + shared libs).
    // Default implementation returns an empty list.
    virtual std::vector<ModuleInfo> enumerateModules() const { return {}; }

protected:
    Mode mode{Mode::External};
    const Arch* arch{X64::instance()};
    std::function<void(const std::string &)> log;
    std::function<bool(StopReason, Address)> eventCallback;
    Debugger* debugger{nullptr};
    std::shared_ptr<Process> process;
};

} // namespace smalldbg
