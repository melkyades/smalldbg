#include "VMSession.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include <iostream>

namespace vmdbg {

std::shared_ptr<smalldbg::Thread> VMSession::resolveThread(uint64_t threadId) const {
    auto proc = debugger().getProcess();
    if (!proc) return nullptr;
    auto opt = proc->getThread(threadId);
    return opt ? *opt : nullptr;
}

std::shared_ptr<smalldbg::Thread> VMSession::threadWithStackPointer(
        const std::function<bool(uint64_t)>& onStack) const {
    auto process = debugger().getProcess();
    // Reading a running target would block until it stops.
    if (!process || !debugger().isStopped()) return nullptr;
    for (const auto& thread : process->threads()) {
        smalldbg::Registers regs;
        if (debugger().getRegisters(thread.get(), regs) != smalldbg::Status::Ok)
            continue;
        if (onStack(regs.sp())) return thread;
    }
    return nullptr;
}

static bool hasFrameOf(smalldbg::Thread& thread, smalldbg::Address function) {
    auto* trace = thread.getStackTrace(256);
    if (!trace) return false;
    // Frames are matched by start address, which does not depend on how a
    // backend spells names.
    for (const auto& frame : trace->getFrames())
        if (frame->functionStart == function) return true;
    return false;
}

std::shared_ptr<smalldbg::Thread> VMSession::threadRunning(const std::string& function) const {
    auto& dbg = debugger();
    if (runningThreadVersion == dbg.stateVersion()) return runningThread;
    auto process = dbg.getProcess();
    if (!process || !dbg.isStopped()) return nullptr;
    auto symbol = dbg.getSymbolProvider()->getSymbolByName(function);
    if (!symbol) return nullptr;

    runningThreadVersion = dbg.stateVersion();
    runningThread = nullptr;
    for (const auto& thread : process->threads()) {
        if (!hasFrameOf(*thread, symbol->address)) continue;
        runningThread = thread;
        break;
    }
    return runningThread;
}

size_t VMSession::pointerSize() const {
    return debugger().arch()->pointerSize();
}

MemoryTypeMap& VMSession::memoryTypes() const {
    if (memoryTypesVersion != debugger().stateVersion()) {
        layOutMemoryTypes();
        memoryTypesVersion = debugger().stateVersion();
    }
    return memTypes;
}

// A module's sections do not move, and reading them costs a round trip per
// section header, so they are read once. An unknown word is read as a pointer.
void VMSession::layOutMemoryTypes() const {
    const MemType word = pointerSize() <= 4 ? MemType::Data4 : MemType::Data8;
    memTypes.clearDefaults();
    memTypes.setFallback(word);

    if (sectionTypes.empty()) {
        for (const auto& module : debugger().getSymbolProvider()->getModules()) {
            auto sections = debugger().moduleSections(module);
            if (sections.empty() && module.endAddress > module.loadAddress)
                sectionTypes.push_back(
                    {module.loadAddress, module.endAddress, MemType::Code});
            for (const auto& section : sections)
                sectionTypes.push_back({section.start, section.end,
                                        section.executable ? MemType::Code : word});
        }
    }
    for (const MemTypeRange& range : sectionTypes)
        memTypes.setDefault(range.start, range.end, range.type);

    inspector().refreshRegions();
    for (const Region& region : inspector().regions())
        memTypes.setDefault(region.start, region.end,
                            region.kind == Region::Kind::Code ? MemType::Code
                                                              : word);
    addMemoryTypeDefaults(memTypes);
}

void VMSession::setOpeningLog(smalldbg::SymbolLoader::LogSink sink) {
    openingLog = std::move(sink);
}

void VMSession::logOpening(const std::string& message) const {
    if (openingLog) openingLog(message);
    else std::cerr << "[" << dialectTag() << "] " << message << std::endl;
}

smalldbg::SymbolLoader& VMSession::symbols() const {
    if (!loader)
        loader = std::make_unique<smalldbg::SymbolLoader>(
            debugger(), [this](const std::string& m) { logOpening(m); });
    return *loader;
}

bool VMSession::loadModuleSymbols(const std::string& module) {
    return symbols().loadAndReport(module);
}

std::string VMSession::runEngineCommand(const std::string& command) {
    std::string output = debugger().executeCommand(command);
    forgetMemoryTypeDefaults();
    targetMayHaveMoved();
    return output;
}

void VMSession::setSymbolSearchPath(const std::string& path) {
    symbols().setSearchPath(path);
}

void VMSession::setVerboseSymbolLogging(bool on) {
    symbols().setVerbose(on);
}

bool VMSession::bringInVMSymbols(const TargetSpec&) {
    VMModule vm = vmModule();
    if (vm.name.empty()) return true;

    smalldbg::SymbolState state = symbols().load(vm.name);
    if (state == smalldbg::SymbolState::Missing && !vm.needsSymbolFile) {
        logOpening("no symbol file for " + vm.name + ", which is no obstacle"
                   " here: the globals this reads are exported.");
        return true;
    }
    return symbols().report(vm.name, state, vm.note);
}

bool VMSession::open(const TargetSpec& target) {
    if (readsWithoutEngine(target)) return onTargetOpened(target);

    if (openInEngine(debugger(), target) != smalldbg::Status::Ok) return false;

    // A name given without a module is looked for in the VM's module first.
    if (VMModule vm = vmModule(); !vm.name.empty())
        debugger().getSymbolProvider()->preferModule(vm.name);

    // A recorded target is read through the VM's symbols, so without them it
    // is refused rather than read as empty.
    if (isRecordedTarget(target.kind)) {
        symbols().useSymbolsBeside(target.path);
        if (!bringInVMSymbols(target)) return false;
        symbols().reportModules();
    }

    if (!onTargetOpened(target)) return false;

    // The class table names frames, threads and processes, so the session
    // builds it now. A VM that has not started yet returns false, and is asked
    // again on first use.
    discoverClasses();
    return true;
}

bool VMSession::resume() {
    beforeTargetRuns();
    return debugger().resume() == smalldbg::Status::Ok;
}

bool VMSession::suspend() {
    if (debugger().suspend() != smalldbg::Status::Ok) return false;
    afterTargetStops();
    return true;
}

bool VMSession::step() {
    beforeTargetRuns();
    bool ok = debugger().step() == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::stepOver() {
    beforeTargetRuns();
    bool ok = debugger().stepOver() == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::stepOut() {
    beforeTargetRuns();
    bool ok = debugger().stepOut() == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::stepBack() {
    beforeTargetRuns();
    bool ok = debugger().stepBack() == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::reverseStepOver() {
    auto thread = debugger().getCurrentThread();
    if (!thread) return false;
    beforeTargetRuns();
    bool ok = debugger().reverseStepOver(thread.get()) == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::reverseStepOut() {
    auto thread = debugger().getCurrentThread();
    if (!thread) return false;
    beforeTargetRuns();
    bool ok = debugger().reverseStepOut(thread.get()) == smalldbg::Status::Ok;
    afterTargetStops();
    return ok;
}

bool VMSession::stepOver(int /*frameIndex*/) { return stepOver(); }
// How long a run to an address may take before the target is suspended.
static constexpr int kRunToTimeoutMs = 30000;

bool VMSession::runToAddress(uint64_t address) {
    beforeTargetRuns();
    bool reached = debugger().runTo(address, kRunToTimeoutMs)
                   == smalldbg::Status::Ok;
    afterTargetStops();
    return reached;
}

bool VMSession::reverseRunToAddress(uint64_t address) {
    beforeTargetRuns();
    bool reached = debugger().reverseRunTo(address, kRunToTimeoutMs)
                   == smalldbg::Status::Ok;
    afterTargetStops();
    return reached;
}

bool VMSession::setBreakpoint(uint64_t address, const std::string& name) {
    return debugger().setBreakpoint(address, name) == smalldbg::Status::Ok;
}

bool VMSession::clearBreakpoint(uint64_t address) {
    return debugger().clearBreakpoint(address) == smalldbg::Status::Ok;
}

} // namespace vmdbg
