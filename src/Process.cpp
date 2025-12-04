#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "backends/Backend.h"

namespace smalldbg {

Process::Process(Backend* be, int p) 
    : backend(be), pid(p), firstThread(nullptr) {
}

void Process::registerThread(ThreadId tid) {
    auto thread = std::make_shared<Thread>(backend, this, tid);
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
    if (!backend) return Status::NotAttached;
    return backend->readMemory(address, outBuf, size);
}

Status Process::writeMemory(Address address, const void* data, size_t size) {
    if (!backend) return Status::NotAttached;
    return backend->writeMemory(address, data, size);
}

bool Process::isAttached() const {
    if (!backend) return false;
    return backend->isAttached();
}

StopReason Process::getStopReason() const {
    if (!backend) return StopReason::None;
    return backend->getStopReason();
}

bool Process::isStopped() const {
    if (!backend) return false;
    return backend->isStopped();
}

Address Process::getStopAddress() const {
    if (!backend) return 0;
    return backend->getStopAddress();
}

} // namespace smalldbg
