#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include <algorithm>
#include <iostream>
#include <sstream>

#include "backends/Backend.h"
#include "backends/WindowsBackend.h"
#include "backends/PtraceBackend.h"

namespace smalldbg {

Debugger::Debugger(Mode m, Arch arch) : backend(nullptr) {
    // Platform selection for backend
#ifdef _WIN32
    backend = new WindowsBackend(this, m, arch);
#else
    backend = new PtraceBackend(this, m, arch);
#endif
}

Debugger::~Debugger(){ delete backend; }

Status Debugger::attach(int pid) {
    return backend->attach(pid);
}

Status Debugger::launch(const std::string &path, const std::vector<std::string> &args) {
    return backend->launch(path, args);
}

Status Debugger::detach() {
    auto status = backend->detach();
    if (status == Status::Ok) {
        selectedThread.reset();
    }
    return status;
}

Status Debugger::resume() {
    return backend->resume();
}

Status Debugger::step() {
    auto proc = backend->getProcess();
    auto thread = selectedThread ? selectedThread : (proc ? proc->primaryThread() : nullptr);
    return backend->step(thread.get());
}

Status Debugger::suspend() {
    return backend->suspend();
}

Status Debugger::setBreakpoint(Address addr, const std::string &name) {
    return backend->setBreakpoint(addr, name);
}

Status Debugger::clearBreakpoint(Address addr) {
    return backend->clearBreakpoint(addr);
}

std::vector<Breakpoint> Debugger::listBreakpoints() const {
    return backend->listBreakpoints();
}

Status Debugger::readMemory(Address address, void *outBuf, size_t size) const {
    return backend->readMemory(address, outBuf, size);
}

Status Debugger::writeMemory(Address address, const void *data, size_t size) {
    return backend->writeMemory(address, data, size);
}

Status Debugger::getRegisters(Registers &out) const {
    if (!backend->isStopped()) {
        return Status::Error;
    }
    return backend->getRegisters(selectedThread.get(), out);
}

bool Debugger::isAttached() const { return backend->isAttached(); }

std::optional<int> Debugger::attachedPid() const { return backend->attachedPid(); }

std::shared_ptr<Process> Debugger::getProcess() {
    return backend->getProcess();
}

std::shared_ptr<Thread> Debugger::getCurrentThread() {
    return selectedThread;
}

void Debugger::setCurrentThread(std::shared_ptr<Thread> thread) {
    selectedThread = thread;
}

StopReason Debugger::getStopReason() const { return backend->getStopReason(); }

bool Debugger::isStopped() const { return backend->isStopped(); }

Address Debugger::getStopAddress() const { return backend->getStopAddress(); }

void Debugger::setLogCallback(std::function<void(const std::string &)> cb) { backend->setLogCallback(std::move(cb)); }

void Debugger::setEventCallback(std::function<void(StopReason, Address)> cb) { backend->setEventCallback(std::move(cb)); }

StopReason Debugger::waitForEvent(StopReason reason, int timeout_ms) {
    return backend->waitForEvent(reason, timeout_ms);
}

} // namespace smalldbg
