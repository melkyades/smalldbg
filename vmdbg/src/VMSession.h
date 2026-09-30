#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace smalldbg {
    class Debugger;
    class Thread;
}

namespace vmdbg {

class VMInspector;

/**
 * One connection to one virtual machine: what moves it and what its runtime
 * holds, as values rather than as a wire format. What a caller does with
 * them is no concern of this layer.
 **/
class VMSession {
public:
    virtual ~VMSession() = default;

    // ---- session lifecycle ----
    virtual bool launch(const std::string& target,
                        const std::vector<std::string>& args = {}) = 0;
    virtual bool attach(int pid) = 0;
    virtual void detach() = 0;
    virtual bool isActive() const = 0;
    virtual std::optional<int> getPid() const = 0;

    // ---- debug control ----
    virtual bool resume() = 0;
    virtual bool suspend() = 0;
    virtual bool step() = 0;
    virtual bool stepOver() = 0;
    virtual bool stepOver(int frameIndex) = 0;
    virtual bool stepOut() = 0;
    virtual bool stepBack() = 0;
    virtual bool reverseStepOver() = 0;
    virtual bool reverseStepOut() = 0;

    // ---- breakpoints ----
    virtual bool setBreakpoint(uint64_t address, const std::string& name = "") = 0;
    virtual bool clearBreakpoint(uint64_t address) = 0;

    // ---- state queries ----
    virtual std::string getStopReason() const = 0;

    // ---- green threads (Smalltalk-level) ----
    virtual void refreshGreenThreads() = 0;
    virtual int greenThreadCount() const = 0;
    virtual std::string getGreenThreadName(int threadIndex) const = 0;
    /// The green thread this OS thread is currently executing, if any.
    virtual std::string greenThreadOn(uint64_t /*nativeThreadId*/) const { return {}; }

    // ---- classes ----
    virtual bool discoverClasses() = 0;

    // ---- underlying debugger / VM inspector ----
    virtual smalldbg::Debugger* getDebugger() const = 0;
    virtual VMInspector* getInspector() const = 0;

    // ---- thread helpers ----
    std::shared_ptr<smalldbg::Thread> resolveThread(uint64_t threadId) const;
    std::shared_ptr<smalldbg::Thread> primaryThread() const;

    /// The target's pointer width, or the host's while there is no target.
    size_t pointerSize() const;

protected:
    /// Runs before a stack walk: an unwind leaves the engine unable to serve
    /// some reads, so a dialect reads what it needs for frames here.
    virtual void prepareFrames() const {}
};

} // namespace vmdbg
