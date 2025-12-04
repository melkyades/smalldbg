#include "PtraceBackend.h"
#include "smalldbg/Debugger.h"
#include <cstring>

namespace smalldbg {

PtraceBackend::PtraceBackend(Debugger* dbg, Mode m, Arch a) : Backend(dbg, m, a) {
}

PtraceBackend::~PtraceBackend() {
    if (attached) {
        detach();
    }
}

Status PtraceBackend::attach(int pid) {
    // TODO: implement ptrace attach
    (void)pid;
    return Status::Error;
}

Status PtraceBackend::launch(const std::string &path, const std::vector<std::string> &args) {
    // TODO: implement ptrace launch
    (void)path;
    (void)args;
    return Status::Error;
}

Status PtraceBackend::detach() {
    // TODO: implement ptrace detach
    if (!attached) return Status::Error;
    attached = false;
    targetPid = -1;
    return Status::Ok;
}

Status PtraceBackend::resume() {
    // TODO: implement ptrace resume
    return Status::Error;
}

Status PtraceBackend::step(Thread* thread) {
    // TODO: implement ptrace step
    (void)thread;
    return Status::Error;
}

Status PtraceBackend::suspend() {
    // TODO: implement ptrace suspend
    return Status::Error;
}

Status PtraceBackend::setBreakpoint(Address addr, const std::string &name) {
    // TODO: implement ptrace breakpoint
    (void)addr;
    (void)name;
    return Status::Error;
}

Status PtraceBackend::clearBreakpoint(Address addr) {
    // TODO: implement ptrace breakpoint removal
    (void)addr;
    return Status::Error;
}

std::vector<Breakpoint> PtraceBackend::listBreakpoints() const {
    return bps;
}

Status PtraceBackend::readMemory(Address address, void *outBuf, size_t size) const {
    // TODO: implement ptrace memory read
    (void)address;
    (void)outBuf;
    (void)size;
    return Status::Error;
}

Status PtraceBackend::writeMemory(Address address, const void *data, size_t size) {
    // TODO: implement ptrace memory write
    (void)address;
    (void)data;
    (void)size;
    return Status::Error;
}

Status PtraceBackend::getRegisters(Thread* thread, Registers &out) const {
    // TODO: implement ptrace register read
    (void)thread;
    std::memset(&out, 0, sizeof(out));
    out.arch = arch;
    return Status::Error;
}

StopReason PtraceBackend::waitForEvent(StopReason reason, int timeout_ms) {
    // TODO: implement ptrace event wait
    (void)reason;
    (void)timeout_ms;
    return StopReason::None;
}

} // namespace smalldbg
