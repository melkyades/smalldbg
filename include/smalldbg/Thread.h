// Thread abstraction - cross-platform thread handle
#pragma once

#include "Types.h"
#include <memory>
#include <vector>

namespace smalldbg {

class Process;
class StackTrace;
class SymbolProvider;
class Debugger;

class Thread {
public:
    Thread(Process* proc, ThreadId tid);
    ~Thread();

    // Thread identification
    ThreadId getThreadId() const { return threadId; }
    Process* getProcess() const { return process; }
    Debugger* getDebugger() const;
    SymbolProvider* getSymbolProvider() const;
    
    // Register access
    Status getRegisters(Registers& out) const;
    
    // Stack inspection helpers
    Address getInstructionPointer() const;
    Address getStackPointer() const;
    Address getFramePointer() const;

    // The thread's stack, unwound on first use and kept until the target
    // moves. Asking for more frames than the kept trace was unwound with
    // unwinds again, so a trace may hold more frames than were asked for.
    // Returns null when the stack cannot be unwound.
    StackTrace* getStackTrace(size_t maxFrames = 64) const;

private:
    Process* process;
    ThreadId threadId;
    mutable std::unique_ptr<StackTrace> trace;
    mutable uint64_t traceVersion{0};  // debugger stateVersion the trace is from
    mutable size_t traceFrames{0};     // maxFrames it was unwound with
};

} // namespace smalldbg
