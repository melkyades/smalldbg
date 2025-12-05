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
    ~Thread() = default;

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

    // Stack trace - returns nullptr on failure
    StackTrace* getStackTrace(size_t maxFrames = 64) const;

private:
    Process* process;
    ThreadId threadId;
};

} // namespace smalldbg
