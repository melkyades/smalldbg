#pragma once

#include "../../include/smalldbg/Types.h"
#include "../../include/smalldbg/Process.h"
#include "../../include/smalldbg/StackTrace.h"
#include "../../include/smalldbg/NativeUnwinder.h"
#include "../../include/smalldbg/Snapshot.h"
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
    virtual Status launch(const std::string &path, const std::vector<std::string> &args,
                          const std::string &workingDir) = 0;
    virtual Status detach() = 0;

    virtual Status resume() = 0;
    virtual Status step(Thread* thread) = 0;
    virtual Status suspend() = 0; // Interrupt running process

    // Stepping over a call and out of a frame need nothing but breakpoints, so
    // every backend has them; one whose engine does better says so.
    virtual Status stepOver(Thread* thread);
    virtual Status stepOut(Thread* thread);
    
    // --- Reverse debugging (TTD) ---
    // Default implementations return NotSupported; override in backends that support TTD
    virtual Status openTrace(const std::string& tracePath) { (void)tracePath; return Status::NotSupported; }
    virtual Status stepBack(Thread* thread) { (void)thread; return Status::NotSupported; }
    virtual Status reverseStepOver(Thread* thread) { (void)thread; return Status::NotSupported; }
    virtual Status reverseStepOut(Thread* thread) { (void)thread; return Status::NotSupported; }
    virtual Status reverseResume() { return Status::NotSupported; }

    // ---- trace replay: a backend that replays no trace has none of this ----
    virtual std::optional<TracePosition> tracePosition() const { return std::nullopt; }
    virtual std::optional<std::pair<TracePosition, TracePosition>> traceExtent() const {
        return std::nullopt;
    }
    virtual Status seekTrace(const TracePosition&) { return Status::NotSupported; }
    virtual Status seekTraceFraction(double) { return Status::NotSupported; }
    virtual std::optional<TracePosition> lastExecution(Address) const {
        return std::nullopt;
    }
    virtual bool isTTDTrace() const { return false; }

    // --- Post-mortem crash-dump loading ---
    // Open a crash/WER dump (.dmp) as a frozen, read-only process snapshot.
    // Default returns NotSupported; override in backends that support it.
    virtual Status openDump(const std::string& dumpPath) { (void)dumpPath; return Status::NotSupported; }
    virtual bool isDumpFile() const { return false; }

    // Memory laid out by the caller, which never runs.
    virtual Status openSnapshot(const std::vector<SnapshotRegion>&) { return Status::NotSupported; }

    virtual Status setBreakpoint(Address addr, const std::string &name) = 0;
    virtual Status clearBreakpoint(Address addr) = 0;
    virtual std::vector<Breakpoint> listBreakpoints() const = 0;

    // HW watchpoint — see Debugger::setWatchpoint. Default: NotSupported.
    virtual Status setWatchpoint(Address /*addr*/, uint64_t /*match*/,
                                 uint64_t /*mask*/) { return Status::NotSupported; }

    virtual Status readMemory(Address address, void *outBuf, size_t size) const = 0;
    virtual Status writeMemory(Address address, const void *data, size_t size) = 0;
    virtual Status getRegisters(Thread* thread, Registers &out) const = 0;
    
    // Stack unwinding: restore caller's register state from current frame
    // Returns Status::Ok if successful, Status::Error if no unwind info available
    virtual Status recoverCallerRegisters(Registers& regs) const = 0;

    // Functions inlined into the code at `ip`, innermost first. Needs the
    // frame's sp/fp because the engine resolves inline call sites against a
    // frame context. Backends without inline info return nothing.
    virtual std::vector<InlineFrameInfo> getInlineFrames(
        Address /*ip*/, Address /*sp*/, Address /*fp*/) const { return {}; }

    // The debugger's lowest-priority unwinder, so it handles any frame no
    // other unwinder does. By default the native one, which unwinds a frame at
    // a time; a backend that can walk the stack itself returns its own.
    virtual std::unique_ptr<StackUnwinder> createUnwinder() const {
        return std::make_unique<NativeUnwinder>();
    }

    virtual bool isAttached() const { return false; }
    std::optional<uintptr_t> attachedPid() const {
        if (process) return process->getPid();
        return std::nullopt;
    }
    
    virtual StopReason getStopReason() const = 0;
    virtual bool isStopped() const = 0;
    virtual Address getStopAddress() const = 0;
    // The exception the target is stopped on. Returns nothing when the stop
    // was not an exception, or when the backend cannot tell.
    virtual std::optional<ExceptionInfo> getStopException() const { return std::nullopt; }
    
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

    // The threads the target has right now. Returns an empty list for a backend
    // that learns of threads only from create and exit events.
    virtual std::vector<ThreadId> enumerateThreads() const { return {}; }

    // Brings the process's thread list in line with the target. A backend that
    // cannot enumerate leaves the list to the events it reports.
    void refreshThreads() {
        if (!process) return;
        auto live = enumerateThreads();
        if (live.empty()) return;
        process->syncThreads(live);
    }

    // The target's architecture, updated once the backend has identified it.
    const Arch* getArch() const { return arch; }

    // The debugger's state version: it changes whenever the target may have
    // moved, so anything read off the target, such as its modules, can be
    // cached against it.
    uint64_t targetVersion() const;

protected:
    /** Run until the frame `depth` below the current one is returned to. **/
    Status runToFrameReturn(Thread* thread, size_t depth);
    /** Run until `address` is reached, by a breakpoint taken away after. **/
    Status runTo(Address address);

    Mode mode{Mode::External};
    const Arch* arch{X64::instance()};
    std::function<void(const std::string &)> log;
    std::function<bool(StopReason, Address)> eventCallback;
    Debugger* debugger{nullptr};
    std::shared_ptr<Process> process;
};

} // namespace smalldbg
