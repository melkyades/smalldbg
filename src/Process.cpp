#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Debugger.h"

#include <algorithm>

namespace smalldbg {

Process::Process(Debugger* dbg, uintptr_t p) 
    : debugger(dbg), pid(p), firstThread(nullptr) {
}

void Process::registerThread(ThreadId tid) {
    auto thread = std::make_shared<Thread>(this, tid);
    threadMap[tid] = thread;
    
    // First thread becomes primary
    if (!firstThread) {
        firstThread = thread;
    }
}

static bool contains(const std::vector<ThreadId>& ids, ThreadId tid) {
    return std::find(ids.begin(), ids.end(), tid) != ids.end();
}

void Process::dropDeadThreads(const std::vector<ThreadId>& live) {
    for (auto it = threadMap.begin(); it != threadMap.end();) {
        if (contains(live, it->first)) { ++it; continue; }
        it = threadMap.erase(it);
    }
}

void Process::registerNewThreads(const std::vector<ThreadId>& live) {
    for (ThreadId tid : live)
        if (threadMap.find(tid) == threadMap.end()) registerThread(tid);
}

// Under replay the set of threads changes in both directions, so a list that
// only grows describes no single instant.
void Process::syncThreads(const std::vector<ThreadId>& live) {
    dropDeadThreads(live);
    registerNewThreads(live);
    // The primary thread stays while it lives; the first live one replaces it.
    if (firstThread && contains(live, firstThread->getThreadId())) return;
    firstThread = live.empty() ? nullptr : threadMap[live.front()];
}

std::vector<std::shared_ptr<Thread>> Process::threads() {
    std::vector<std::shared_ptr<Thread>> result;
    for (const auto& pair : threadMap) {
        result.push_back(pair.second);
    }
    return result;
}

std::optional<std::shared_ptr<Thread>> Process::getThread(ThreadId tid) {
    auto it = threadMap.find(tid);
    if (it != threadMap.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::shared_ptr<Thread> Process::primaryThread() {
    return firstThread;
}

Status Process::readMemory(Address address, void* outBuf, size_t size) const {
    return debugger->readMemory(address, outBuf, size);
}

Status Process::writeMemory(Address address, const void* data, size_t size) {
    return debugger->writeMemory(address, data, size);
}

bool Process::isAttached() const {
    return debugger->isAttached();
}

StopReason Process::getStopReason() const {
    return debugger->getStopReason();
}

bool Process::isStopped() const {
    return debugger->isStopped();
}

Address Process::getStopAddress() const {
    return debugger->getStopAddress();
}

} // namespace smalldbg
