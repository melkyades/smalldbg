// Thread abstraction - cross-platform thread handle
#pragma once

#include "Types.h"
#include <memory>

namespace smalldbg {

class Backend;
class Process;

class Thread {
public:
    Thread(Backend* be, Process* proc, ThreadId tid);
    ~Thread() = default;

    // Thread identification
    ThreadId getThreadId() const { return threadId; }
    Process* getProcess() const { return process; }
    
    // Register access
    Status getRegisters(Registers& out) const;
    
    // Stack inspection helpers
    Address getInstructionPointer() const;
    Address getStackPointer() const;
    Address getFramePointer() const;

private:
    Backend* backend;
    Process* process;
    ThreadId threadId;
};

} // namespace smalldbg
