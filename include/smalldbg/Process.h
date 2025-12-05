// Process abstraction - cross-platform process handle
#pragma once

#include "Types.h"
#include <vector>
#include <memory>
#include <optional>
#include <map>

namespace smalldbg {

class Thread;
class Debugger;

class Process {
public:
    Process(Debugger* dbg, int pid);
    ~Process() = default;

    // Process identification
    int getPid() const { return pid; }
    
    // Thread enumeration
    std::vector<std::shared_ptr<Thread>> threads();
    std::optional<std::shared_ptr<Thread>> getThread(ThreadId tid);
    std::shared_ptr<Thread> primaryThread();
    
    // Memory operations
    Status readMemory(Address address, void* outBuf, size_t size) const;
    Status writeMemory(Address address, const void* data, size_t size);
    
    // State
    bool isAttached() const;
    StopReason getStopReason() const;
    bool isStopped() const;
    Address getStopAddress() const;
    
    Debugger* getDebugger() const { return debugger; }

    // Internal: called by backend when thread is created
    void registerThread(ThreadId tid);

private:
    Debugger* debugger{nullptr};
    int pid;
    std::map<ThreadId, std::shared_ptr<Thread>> threadMap;
    std::shared_ptr<Thread> firstThread;
};

} // namespace smalldbg
