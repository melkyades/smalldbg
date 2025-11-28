#include "smalldbg/Debugger.h"
#include <algorithm>
#include <iostream>

#include "backends/Backend.h"
#include "backends/WindowsBackend.h"

namespace smalldbg {

Debugger::Debugger(Mode m, Arch arch) : backend(nullptr) {
    // Platform selection for backend - currently we only implement Windows
#ifdef _WIN32
    (void)arch; // arch may be used later
    backend = new WindowsBackend(m, arch);
#else
    (void)m; (void)arch;
    backend = nullptr; // unimplemented platform
#endif
}

Debugger::~Debugger(){ delete backend; }

Status Debugger::attach(int pid) {
    if (!backend) return Status::Error;
    return backend->attach(pid);
}

Status Debugger::launch(const std::string &path, const std::vector<std::string> &args) {
    if (!backend) return Status::Error;
    return backend->launch(path, args);
}

Status Debugger::detach() {
    if (!backend) return Status::NotAttached;
    return backend->detach();
}

Status Debugger::resume() {
    if (!backend) return Status::NotAttached;
    return backend->resume();
}

Status Debugger::step() {
    if (!backend) return Status::NotAttached;
    return backend->step();
}

Status Debugger::setBreakpoint(Address addr, const std::string &name) {
    if (!backend) return Status::NotAttached;
    return backend->setBreakpoint(addr, name);
}

Status Debugger::clearBreakpoint(Address addr) {
    if (!backend) return Status::NotAttached;
    return backend->clearBreakpoint(addr);
}

std::vector<Breakpoint> Debugger::listBreakpoints() const {
    if (!backend) return {};
    return backend->listBreakpoints();
}

Status Debugger::readMemory(Address address, void *outBuf, size_t size) const {
    if (!backend) return Status::NotAttached;
    return backend->readMemory(address, outBuf, size);
}

Status Debugger::writeMemory(Address address, const void *data, size_t size) {
    if (!backend) return Status::NotAttached;
    return backend->writeMemory(address, data, size);
}

Status Debugger::getRegisters(Registers &out) const {
    if (!backend) return Status::NotAttached;
    return backend->getRegisters(out);
}

bool Debugger::isAttached() const { return backend && backend->isAttached(); }

std::optional<int> Debugger::attachedPid() const { return backend ? backend->attachedPid() : std::nullopt; }

void Debugger::setLogCallback(std::function<void(const std::string &)> cb) { if (backend) backend->setLogCallback(std::move(cb)); }

} // namespace smalldbg
