#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/StackUnwinder.h"
#include "platform/Platform.h"
#include <algorithm>
#include <sstream>

#include "backends/Backend.h"
#include "backends/SnapshotBackend.h"
#ifdef _WIN32
#include "backends/WindowsBackend.h"
#include "platform/windows/WoW64SyscallUnwinder.h"
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

// The one backend this Debugger will have, chosen for what it debugs.
static Backend* backendFor(Debugger* debugger, Mode mode, const Arch* arch,
                           Debuggee debuggee) {
    if (debuggee == Debuggee::Snapshot) return new SnapshotBackend(debugger, mode, arch);
#if defined(_WIN32) && defined(SMALLDBG_USE_DBGENG)
    if (debuggee == Debuggee::Trace) return new TTDBackend(debugger, mode, arch);
    return new DbgEngBackend(debugger, mode, arch);
#elif defined(_WIN32)
    return new WindowsBackend(debugger, mode, arch);
#else
    return new PtraceBackend(debugger, mode, arch);
#endif
}

Debugger::Debugger(Mode mode, const Arch* arch, Debuggee debuggee)
    : backend(backendFor(this, mode, arch ? arch : X64::instance(), debuggee)),
      symbolProvider(std::make_unique<SymbolProvider>(backend)),
      disassembler(std::make_unique<Disassembler>(backend->getArch())) {
#ifdef _WIN32
    unwinders.push_back(std::make_unique<WoW64SyscallUnwinder>());
#endif
    // The backend's unwinder handles any frame, so it has the lowest priority.
    unwinders.push_back(backend->createUnwinder());
}

Debugger::~Debugger(){ delete backend; }

const Arch* Debugger::arch() const {
    return backend->getArch();
}

void Debugger::updateArch(const Arch* arch) {
    disassembler = std::make_unique<Disassembler>(arch);
}

Status Debugger::attach(uintptr_t pid) {
    return backend->attach(pid);
}

Status Debugger::launch(const std::string &path, const std::vector<std::string> &args,
                        const std::string &workingDir) {
    return backend->launch(path, args, workingDir);
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
    if (!selectedThread) return Status::NotFound;
    return step(selectedThread.get());
}

Status Debugger::step(Thread* thread) {
    targetMoved();
    return backend->step(thread);
}

Status Debugger::stepOver() {
    if (!selectedThread) return Status::NotFound;
    return stepOver(selectedThread.get());
}

Status Debugger::stepOver(Thread* thread) {
    targetMoved();
    return backend->stepOver(thread);
}

Status Debugger::stepOut() {
    if (!selectedThread) return Status::NotFound;
    return stepOut(selectedThread.get());
}

Status Debugger::stepOut(Thread* thread) {
    targetMoved();
    return backend->stepOut(thread);
}

// How long the suspend that ends a run-to waits for the target to halt.
static constexpr int kHaltWaitMs = 5000;

Status Debugger::runTo(Address address, int timeoutMs) {
    return runToWith(address, timeoutMs, [this] { return resume(); });
}

Status Debugger::reverseRunTo(Address address, int timeoutMs) {
    if (!isTTDTrace()) return Status::NotSupported;
    return runToWith(address, timeoutMs, [this] { return reverseResume(); });
}

// A breakpoint the user set at `address` is theirs, so only one set here for
// the run is cleared again.
Status Debugger::runToWith(Address address, int timeoutMs,
                           const std::function<Status()>& run) {
    if (!isStopped()) return Status::Busy;
    bool ours = true;
    for (const auto& breakpoint : listBreakpoints())
        if (breakpoint.addr == address) ours = false;
    if (ours && setBreakpoint(address, "run to") != Status::Ok)
        return Status::Error;

    Status status = run();
    if (status == Status::Ok) status = awaitArrival(address, timeoutMs);
    if (ours) clearBreakpoint(address);
    return status;
}

// Any stop ends the wait: one at another breakpoint or on an exception is
// where the run ended, and waiting on would never return.
Status Debugger::awaitArrival(Address address, int timeoutMs) {
    StopReason reason = waitForEvent(StopReason::None, timeoutMs);
    if (reason == StopReason::None) {
        suspend();
        waitForEvent(StopReason::None, kHaltWaitMs);
        return Status::NotFound;
    }
    bool arrived = reason == StopReason::Breakpoint
                   && getStopAddress() == address;
    return arrived ? Status::Ok : Status::NotFound;
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
Status Debugger::openTrace(const std::string& tracePath) {
    return backend->openTrace(tracePath);
}

Status Debugger::stepBack() {
    if (!selectedThread) return Status::NotFound;
    return stepBack(selectedThread.get());
}

Status Debugger::stepBack(Thread* thread) {
    targetMoved();
    return backend->stepBack(thread);
}

Status Debugger::reverseStepOver(Thread* thread) {
    targetMoved();
    return backend->reverseStepOver(thread);
}

Status Debugger::reverseStepOut(Thread* thread) {
    targetMoved();
    return backend->reverseStepOut(thread);
}

Status Debugger::reverseResume() {
    targetMoved();
    return backend->reverseResume();
}

std::optional<TracePosition> Debugger::tracePosition() const {
    return backend->tracePosition();
}

std::optional<std::pair<TracePosition, TracePosition>> Debugger::traceExtent() const {
    return backend->traceExtent();
}

Status Debugger::seekTrace(const TracePosition& position) {
    targetMoved();
    return backend->seekTrace(position);
}

Status Debugger::seekTrace(double percent) {
    targetMoved();
    return backend->seekTraceFraction(percent);
}

std::optional<TracePosition> Debugger::lastExecution(Address address) const {
    return backend->lastExecution(address);
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

Status Debugger::openSnapshot(const std::vector<SnapshotRegion>& regions) {
    return backend->openSnapshot(regions);
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

std::vector<ModuleSection> Debugger::moduleSections(const ModuleInfo& module) const {
    auto read = [this](uint64_t address, void* out, size_t size) {
        return readMemory(address, out, size) == Status::Ok;
    };
    return smalldbg_internal::moduleSections(read, module.loadAddress,
                                             module.endAddress);
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

const ThreadIdentity& Debugger::threadIdentity(Thread& thread) {
    if (identitiesVersion != targetVersion) {
        identities.clear();
        identitiesVersion = targetVersion;
    }
    auto known = identities.find(thread.getThreadId());
    if (known != identities.end()) return known->second;
    return identities.emplace(thread.getThreadId(), identify(thread)).first->second;
}

static std::string frameLabel(const StackFrame& frame) {
    if (frame.functionName.empty()) return "";
    return frame.moduleName.empty() ? frame.functionName
                                    : frame.moduleName + "!" + frame.functionName;
}

// A walk that runs off the end of a stack it does not understand lands on a
// module's load address, inside its header where no code can be, and the
// symbol engine still names it after the module's first symbol.
static bool isImpossibleFrame(const StackFrame& frame,
                              const std::vector<ModuleInfo>& modules) {
    for (const auto& module : modules)
        if (frame.ip() == module.loadAddress) return true;
    return false;
}

// Returns true for a frame that cannot name a thread: one the system put on
// every thread's stack, one that cannot be real, or one with no name.
static bool namesNoThread(const StackFrame& frame,
                          const std::vector<ModuleInfo>& modules) {
    if (isImpossibleFrame(frame, modules)) return true;
    // A frame matched to a module only carries the module as its function.
    const std::string& module = frame.moduleName.empty() ? frame.functionName
                                                         : frame.moduleName;
    if (smalldbg_internal::isThreadStarter(module, frame.functionName))
        return true;
    std::string label = frameLabel(frame);
    return label.empty() || label.find("<unknown>") != std::string::npos;
}

// The stack is read from its base: the top only says where a thread waits, and
// most threads wait in the same few places.
ThreadIdentity Debugger::identify(Thread& thread) {
    ThreadIdentity identity;
    Registers regs;
    if (getRegisters(&thread, regs) != Status::Ok || regs.sp() == 0)
        return identity;
    StackTrace* trace = thread.getStackTrace(512);
    if (!trace || trace->getFrames().empty()) return identity;
    identity.hasContext = true;

    auto modules = symbolProvider->getModules();
    const auto& frames = trace->getFrames();
    for (auto frame = frames.rbegin(); frame != frames.rend(); ++frame) {
        if (namesNoThread(**frame, modules)) continue;
        identity.name = frameLabel(**frame);
        break;
    }
    return identity;
}

StopReason Debugger::getStopReason() const { return backend->getStopReason(); }

const char* stopReasonName(StopReason reason) {
    switch (reason) {
    case StopReason::None:              return "no stop";
    case StopReason::ProcessCreated:    return "process created";
    case StopReason::ThreadCreated:     return "thread created";
    case StopReason::ModuleLoaded:      return "module loaded";
    case StopReason::ModuleUnloaded:    return "module unloaded";
    case StopReason::InitialBreakpoint: return "initial breakpoint";
    case StopReason::Breakpoint:        return "breakpoint";
    case StopReason::SingleStep:        return "single step";
    case StopReason::Exception:         return "exception";
    case StopReason::ProcessExit:       return "process exit";
    case StopReason::EndOfTrace:        return "end of trace";
    }
    return "unknown";
}

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
