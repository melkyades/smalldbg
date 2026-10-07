#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/StackUnwinder.h"
#include <algorithm>
#include <sstream>

#include "backends/Backend.h"
#ifdef _WIN32
#include "backends/WindowsBackend.h"
#include "backends/DbgEngBackend.h"
#include "backends/TTDBackend.h"
#else
#include "backends/PtraceBackend.h"
#endif

namespace smalldbg {

namespace {
thread_local bool engineBusy = false;
}

void markEngineBusy() { engineBusy = true; }

void clearEngineBusy() { engineBusy = false; }

bool engineWasBusy() { return engineBusy; }

Debugger::Debugger(Mode m, const Arch* arch)
    : backend(nullptr), symbolProvider(nullptr), mode(m),
      initialArch(arch ? arch : X64::instance()) {
#ifdef _WIN32
  #ifdef SMALLDBG_USE_DBGENG
    useBackend(new DbgEngBackend(this, mode, initialArch));
  #else
    useBackend(new WindowsBackend(this, mode, initialArch));
  #endif
#else
    useBackend(new PtraceBackend(this, mode, initialArch));
#endif

    disassembler = std::make_unique<Disassembler>(initialArch);

    // The backend's unwinder handles any frame, so it has the lowest priority.
    unwinders.push_back(backend->createUnwinder());
}

Debugger::~Debugger(){ delete backend; }

// Symbol resolution is tied to the backend, so it is rebuilt alongside it.
// Backends register their own symbol backends during session init.
void Debugger::useBackend(Backend* newBackend) {
    delete backend;
    backend = newBackend;
    if (!unwinders.empty()) unwinders.back() = backend->createUnwinder();
    symbolProvider = std::make_unique<SymbolProvider>(backend);
}

const Arch* Debugger::arch() const {
    return backend ? backend->getArch() : initialArch;
}

void Debugger::updateArch(const Arch* arch) {
    disassembler = std::make_unique<Disassembler>(arch);
}

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
    targetMoved();
    return backend->resume();
}

Status Debugger::step() {
    auto proc = backend->getProcess();
    auto thread = selectedThread ? selectedThread : proc->primaryThread();
    return step(thread.get());
}

Status Debugger::step(Thread* thread) {
    targetMoved();
    return backend->step(thread);
}

Status Debugger::stepOver() {
    auto proc = backend->getProcess();
    auto thread = selectedThread ? selectedThread : proc->primaryThread();
    return stepOver(thread.get());
}

Status Debugger::stepOver(Thread* thread) {
    targetMoved();
    return backend->stepOver(thread);
}

Status Debugger::stepOut() {
    auto proc = backend->getProcess();
    auto thread = selectedThread ? selectedThread : proc->primaryThread();
    return stepOut(thread.get());
}

Status Debugger::stepOut(Thread* thread) {
    targetMoved();
    return backend->stepOut(thread);
}

Status Debugger::suspend() {
    targetMoved();
    return backend->suspend();
}

// Enumerating costs an engine round trip, so it is done only after a move.
void Debugger::refreshThreads() {
    if (threadsVersion == targetVersion) return;
    threadsVersion = targetVersion;
    backend->refreshThreads();
}

// --- TTD (Time Travel Debugging) ---
// Replay is a different backend, not a mode of the live one, and which it is
// only becomes known here — the constructor has no target to look at yet.
Status Debugger::openTrace(const std::string& tracePath) {
#if defined(_WIN32) && defined(SMALLDBG_USE_DBGENG)
    useBackend(new TTDBackend(this, mode, initialArch));
#endif
    return backend->openTrace(tracePath);
}

Status Debugger::stepBack() {
    auto proc = backend->getProcess();
    auto thread = selectedThread ? selectedThread : proc->primaryThread();
    return stepBack(thread.get());
}

Status Debugger::stepBack(Thread* thread) {
    targetMoved();
    return backend->stepBack(thread);
}

Status Debugger::reverseStepOver(Thread* thread) {
    targetMoved();
    return backend->reverseStepOver(thread);
}

Status Debugger::reverseResume() {
    targetMoved();
    return backend->reverseResume();
}

bool Debugger::isTTDTrace() const {
    return backend->isTTDTrace();
}

Status Debugger::openDump(const std::string& dumpPath) {
    return backend->openDump(dumpPath);
}

bool Debugger::isDumpFile() const {
    return backend->isDumpFile();
}

// A command may run or seek the target, and telling which would mean parsing
// the command language, so it counts as a move.
std::string Debugger::executeCommand(const std::string& cmd) const {
    targetMoved();
    return backend->executeCommand(cmd);
}

Status Debugger::setBreakpoint(Address addr, const std::string &name) {
    return backend->setBreakpoint(addr, name);
}

Status Debugger::setWatchpoint(Address addr, uint64_t match, uint64_t mask) {
    return backend->setWatchpoint(addr, match, mask);
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

std::vector<InlineFrameInfo> Debugger::getInlineFrames(Address ip, Address sp, Address fp) const {
    return backend->getInlineFrames(ip, sp, fp);
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

std::optional<ExceptionInfo> Debugger::getStopException() const {
    return backend->getStopException();
}

void Debugger::setLogCallback(std::function<void(const std::string &)> cb) { backend->setLogCallback(std::move(cb)); }

void Debugger::setEventCallback(std::function<bool(StopReason, Address)> cb) { backend->setEventCallback(std::move(cb)); }

// The target stops somewhere new, so the wait counts as a move.
StopReason Debugger::waitForEvent(StopReason reason, int timeout_ms) {
    targetMoved();
    return backend->waitForEvent(reason, timeout_ms);
}

SymbolProvider* Debugger::getSymbolProvider() {
    return symbolProvider.get();
}

Status Debugger::setSymbolOptions(const SymbolOptions& options) {
    symbolProvider->setOptions(options);
    return Status::Ok;
}

void Debugger::registerUnwinder(std::unique_ptr<StackUnwinder> unwinder) {
    // Above the backend's unwinder, which keeps the lowest priority.
    auto it = unwinders.empty() ? unwinders.end() : std::prev(unwinders.end());
    unwinders.insert(it, std::move(unwinder));
}

} // namespace smalldbg
