// SmallDBG — minimal public debugger API (header)
#pragma once

#include "Types.h"
#include "StackTrace.h"      // InlineFrameInfo
#include "symbols/SymbolProvider.h"  // Need full definition for SymbolOptions default parameter
#include <functional>
#include <vector>
#include <optional>
#include <memory>

#include "Disassembler.h"

namespace smalldbg {

class Backend;
class Process;
class Thread;
class StackUnwinder;

// Whether an engine call was refused on this thread because the debuggee was
// running. Recorded per-thread so that a caller serving one request at a time
// can clear it, do the work, and ask afterwards whether what it produced was
// actually complete, without every layer in between forwarding a Status it
// does not care about.
void markEngineBusy();
void clearEngineBusy();
bool engineWasBusy();

class Debugger {
public:
    explicit Debugger(Mode m, const Arch* arch = nullptr);
    ~Debugger();

    // attach/launch lifecycle
    Status attach(uintptr_t pid);
    Status launch(const std::string &path, const std::vector<std::string> &args = {});
    Status detach();

    // run control. The steps without a thread act on the current one, and
    // return NotFound when there is none.
    Status resume();
    Status step();
    Status step(Thread* thread);
    Status suspend(); // Interrupt/break into running process

    Status stepOver();
    Status stepOver(Thread* thread);
    Status stepOut();
    Status stepOut(Thread* thread);
    
    // --- Reverse debugging (TTD) ---
    Status openTrace(const std::string& tracePath);  // Open a TTD trace file (.run)
    Status stepBack();              // Step backwards on the current thread
    Status stepBack(Thread* thread); // Step backwards on specific thread
    Status reverseStepOver(Thread* thread); // Step backwards over calls on specific thread
    Status reverseResume();         // Run backwards until breakpoint/start
    bool isTTDTrace() const;        // Check if we're replaying a TTD trace

    // --- Post-mortem crash-dump loading ---
    Status openDump(const std::string& dumpPath);  // Open a crash/WER dump (.dmp)
    bool isDumpFile() const;        // Check if we're inspecting a crash dump
    
    // Execute a raw engine command (DbgEng: "kb", "lm", etc.) and return output.
    // Empty string on backends that don't support it.
    std::string executeCommand(const std::string& cmd) const;
    
    // state queries
    StopReason getStopReason() const;
    bool isStopped() const;
    Address getStopAddress() const;
    // The exception the target is stopped on, with its code, address and
    // parameters. Returns nothing when the stop was not an exception.
    std::optional<ExceptionInfo> getStopException() const;
    
    // Wait for debugger to stop with a specific reason (or any reason if None)
    // Returns the actual stop reason, or None if timeout/error
    // timeout_ms: 0 = no wait, -1 = infinite, >0 = timeout in milliseconds
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1);

    // breakpoints
    Status setBreakpoint(Address addr, const std::string &name = {});
    Status clearBreakpoint(Address addr);
    std::vector<Breakpoint> listBreakpoints() const;

    // HW watchpoint (write, 8 bytes). addr=0 clears. match=0 means
    // "log every hit, never break"; non-zero means break when the value
    // at addr matches `(read & mask) == match`. Implemented only by
    // PtraceBackend on macOS/arm64; other backends are no-ops.
    Status setWatchpoint(Address addr, uint64_t match = 0,
                         uint64_t mask = 0xFFFFFFFFFFFFFFFFULL);

    // helpers
    bool isAttached() const;
    std::optional<uintptr_t> attachedPid() const;

    // A number that changes whenever the target may have moved: run, stepped,
    // suspended, waited on or sent a command. Anything read off the target can
    // be cached against it.
    uint64_t stateVersion() const { return targetVersion; }

    // Makes the thread list the target's current one, at most once per state
    // version.
    void refreshThreads();

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
    std::vector<InlineFrameInfo> getInlineFrames(Address ip, Address sp, Address fp) const;

    // Logging callback (simple) — optional
    void setLogCallback(std::function<void(const std::string &)> cb);
    
    // Event callback — called when debugger stops
    // Callback receives (reason, address) - address is relevant for breakpoints/exceptions
    // Return false to stop execution, true to continue
    void setEventCallback(std::function<bool(StopReason, Address)> cb);

    // Symbol support
    SymbolProvider* getSymbolProvider();
    Status setSymbolOptions(const SymbolOptions& options);  // Set options before process creation
    
    // The unwinders a stack trace asks, highest priority first: those added
    // with registerUnwinder(), in the order they were added, then the
    // backend's, which handles any frame.
    void registerUnwinder(std::unique_ptr<StackUnwinder> unwinder);
    const std::vector<std::unique_ptr<StackUnwinder>>& getUnwinders() const { return unwinders; }
    
    Backend* getBackend() const { return backend; }
    Disassembler* getDisassembler() { return disassembler.get(); }

    /// The target's architecture, as the backend currently understands it.
    const Arch* arch() const;

    /// Update arch after the backend detects the target's real architecture
    /// (e.g. a WoW64 process running under a 64-bit host).
    void updateArch(const Arch* arch);

private:
    /// Install a backend, taking ownership and discarding the previous one.
    void useBackend(Backend* newBackend);

    // Called by everything that may move the target.
    void targetMoved() const { targetVersion++; }

    Backend *backend; // pointer to backend implementation
    std::shared_ptr<Thread> selectedThread; // current thread
    std::unique_ptr<SymbolProvider> symbolProvider; // symbol resolution
    std::vector<std::unique_ptr<StackUnwinder>> unwinders; // highest priority first
    std::unique_ptr<Disassembler> disassembler; // disassembler instance
    Mode mode;                  // kept to build a replacement backend
    const Arch* initialArch;
    mutable uint64_t targetVersion{1};
    uint64_t threadsVersion{0};  // targetVersion the thread list is from
};

} // namespace smalldbg
