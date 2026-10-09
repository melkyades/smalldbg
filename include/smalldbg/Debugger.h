// SmallDBG — minimal public debugger API (header)
#pragma once

#include "Types.h"
#include "Snapshot.h"
#include "StackTrace.h"      // InlineFrameInfo
#include "symbols/SymbolProvider.h"  // Need full definition for SymbolOptions default parameter
#include <functional>
#include <map>
#include <string>
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


/** A ThreadIdentity says what a thread was started to do: the first frame,
 *  from the base of its stack, that the system did not put there. **/
struct ThreadIdentity {
    std::string name;        // "module!function"; empty when none was found
    // False for a thread with no registers or stack, such as one a trace
    // lists but never recorded running.
    bool hasContext{false};
};

class Debugger {
public:
    // The backend is chosen here, for what the Debugger is to debug, and kept
    // until it is destroyed: debugging something else takes another Debugger.
    explicit Debugger(Mode m, const Arch* arch = nullptr,
                      Debuggee debuggee = Debuggee::Process);
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

    /** Runs the target until it reaches `address`, waiting at most `timeoutMs`
     *  (-1 waits for good), and suspends it when it does not get there in
     *  time. A breakpoint already set at `address` stays. Returns NotFound
     *  when the target stopped elsewhere or had to be suspended. **/
    Status runTo(Address address, int timeoutMs);
    
    // --- Reverse debugging (TTD) ---
    // Open a TTD trace file (.run). Returns NotSupported unless the Debugger
    // was built for a trace.
    Status openTrace(const std::string& tracePath);
    Status stepBack();              // Step backwards on the current thread
    Status stepBack(Thread* thread); // Step backwards on specific thread
    Status reverseStepOver(Thread* thread); // Step backwards over calls on specific thread
    // Steps backwards out of the current frame, to the call that entered it.
    Status reverseStepOut(Thread* thread);
    Status reverseResume();         // Run backwards until breakpoint/start
    /** Runs a replay backwards until it reaches `address`, the way runTo runs
     *  forwards. Returns NotSupported unless the target is a replay. **/
    Status reverseRunTo(Address address, int timeoutMs);
    bool isTTDTrace() const;        // Check if we're replaying a TTD trace

    // --- Post-mortem crash-dump loading ---
    Status openDump(const std::string& dumpPath);  // Open a crash/WER dump (.dmp)
    bool isDumpFile() const;        // Check if we're inspecting a crash dump

    // --- Snapshots: memory read from files or buffers, which never runs ---
    // Returns NotSupported unless the Debugger was built for a snapshot.
    Status openSnapshot(const std::vector<SnapshotRegion>& regions);
    
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

    /** Returns what `thread` was started to do. The answer unwinds the whole
     *  stack, so it is kept until the target moves, and stays valid until
     *  then. Needs a stopped target. **/
    const ThreadIdentity& threadIdentity(Thread& thread);
    
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

    /** Returns the target's architecture as the backend currently sees it. **/
    const Arch* arch() const;

    /** Sets the architecture once the backend detects the target's real one,
     *  such as a WoW64 process under a 64-bit debugger. **/
    void updateArch(const Arch* arch);

private:
    // Called by everything that may move the target.
    void targetMoved() const { targetVersion++; }

    Status runToWith(Address address, int timeoutMs,
                     const std::function<Status()>& run);
    Status awaitArrival(Address address, int timeoutMs);
    ThreadIdentity identify(Thread& thread);

    Backend *backend; // pointer to backend implementation
    std::shared_ptr<Thread> selectedThread; // current thread
    std::unique_ptr<SymbolProvider> symbolProvider; // symbol resolution
    std::vector<std::unique_ptr<StackUnwinder>> unwinders; // highest priority first
    std::unique_ptr<Disassembler> disassembler; // disassembler instance
    mutable uint64_t targetVersion{1};
    std::map<ThreadId, ThreadIdentity> identities;
    uint64_t identitiesVersion{0};  // targetVersion the identities are from
    uint64_t threadsVersion{0};  // targetVersion the thread list is from
};

} // namespace smalldbg
