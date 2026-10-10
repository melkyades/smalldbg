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
    Process(Debugger* dbg, uintptr_t pid);
    ~Process() = default;

    // Process identification
    uintptr_t getPid() const { return pid; }
    
    /** Returns the threads the target has. A stopped target is asked for its
     *  current ones, at most once each time it moves. **/
    std::vector<std::shared_ptr<Thread>> threads();
    std::optional<std::shared_ptr<Thread>> getThread(ThreadId tid);
    
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

    // Makes the thread list the target's current one: threads it no longer has
    // are dropped and new ones added; the objects of those that stay are kept.
    void syncThreads(const std::vector<ThreadId>& live);

private:
    void dropDeadThreads(const std::vector<ThreadId>& live);
    void registerNewThreads(const std::vector<ThreadId>& live);

    Debugger* debugger{nullptr};
    uintptr_t pid;
    std::map<ThreadId, std::shared_ptr<Thread>> threadMap;
};

} // namespace smalldbg
