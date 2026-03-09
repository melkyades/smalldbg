#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackFrameProcessor.h"
#include "smalldbg/NativeFrameProcessor.h"
#include <algorithm>
#include <sstream>

#include "backends/Backend.h"
#ifdef _WIN32
#include "backends/WindowsBackend.h"
#else
#include "backends/PtraceBackend.h"
#endif

namespace smalldbg {

Debugger::Debugger(Mode m, const Arch* arch) : backend(nullptr), symbolProvider(nullptr) {
    // Platform selection for backend
#ifdef _WIN32
  #ifdef SMALLDBG_USE_DBGENG
    backend = new DbgEngBackend(this, m, arch);
  #else
    backend = new WindowsBackend(this, m, arch);
  #endif
#else
    backend = new PtraceBackend(this, m, arch);
#endif
    
    // Create symbol provider (backends will register their symbol backends)
    symbolProvider = std::make_unique<SymbolProvider>(backend);
    
    // Register the native/C frame processor as the default (always last in chain)
    frameProcessors.push_back(std::make_unique<NativeFrameProcessor>());
}

Debugger::~Debugger(){ delete backend; }

Status Debugger::attach(uintptr_t pid) {
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

Status Debugger::step(Thread* thread) {
    return backend->step(thread);
}

Status Debugger::suspend() {
    return backend->suspend();
}
std::string Debugger::executeCommand(const std::string& cmd) const {
    return backend->executeCommand(cmd);
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

Status Debugger::getRegisters(const Thread* thread, Registers &out) const {
    return backend->getRegisters(const_cast<Thread*>(thread), out);
}

Status Debugger::recoverCallerRegisters(Registers& regs) const {
    return backend->recoverCallerRegisters(regs);
}

bool Debugger::isAttached() const { return backend->isAttached(); }

std::optional<uintptr_t> Debugger::attachedPid() const { return backend->attachedPid(); }

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

void Debugger::setEventCallback(std::function<bool(StopReason, Address)> cb) { backend->setEventCallback(std::move(cb)); }

StopReason Debugger::waitForEvent(StopReason reason, int timeout_ms) {
    return backend->waitForEvent(reason, timeout_ms);
}

SymbolProvider* Debugger::getSymbolProvider() {
    return symbolProvider.get();
}

Status Debugger::setSymbolOptions(const SymbolOptions& options) {
    symbolProvider->setOptions(options);
    return Status::Ok;
}

void Debugger::registerFrameProcessor(std::unique_ptr<StackFrameProcessor> processor) {
    // Insert before the last element (the native fallback processor)
    auto it = frameProcessors.empty() ? frameProcessors.end() : std::prev(frameProcessors.end());
    frameProcessors.insert(it, std::move(processor));
}

} // namespace smalldbg
