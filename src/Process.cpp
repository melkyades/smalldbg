#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

Process::Process(Debugger* dbg, int p) 
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
