#include "VMSession.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include <algorithm>
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

// The write breakpoint lives only for the run, like the one runTo sets, and
// as runTo does, a target that does not get there in time is stopped. A write
// breakpoint stops at the address it watches; any other stop is not a write.
bool VMSession::runToWrite(uint64_t address, size_t size, bool backwards) {
    if (debugger().setWriteBreakpoint(address, size) != smalldbg::Status::Ok) return false;
    beforeTargetRuns();
    const bool started = (backwards ? debugger().reverseResume() : debugger().resume())
                         == smalldbg::Status::Ok;
    const smalldbg::StopReason reason = started
        ? debugger().waitForEvent(smalldbg::StopReason::None, kRunToTimeoutMs)
        : smalldbg::StopReason::None;
    if (started && reason == smalldbg::StopReason::None) debugger().suspend();
    afterTargetStops();
    debugger().clearWriteBreakpoint(address);
    return reason == smalldbg::StopReason::Breakpoint && debugger().getStopAddress() == address;
}

bool VMSession::reverseResume() {
    beforeTargetRuns();
    bool ran = debugger().reverseResume() == smalldbg::Status::Ok
        && debugger().waitForEvent(smalldbg::StopReason::None, kRunToTimeoutMs)
           != smalldbg::StopReason::None;
    afterTargetStops();
    return ran;
}

// How many screen updates in a row may show the same picture before the
// search for a different one gives up.
static constexpr int kMaxSameFrames = 64;

std::vector<uint64_t> VMSession::screenUpdateAddresses() const {
    std::vector<uint64_t> addresses;
    auto* provider = debugger().getSymbolProvider();
    for (const std::string& name : screenUpdateFunctions())
        if (auto symbol = provider->getSymbolByName(name))
            addresses.push_back(symbol->address);
    return addresses;
}

// The breakpoints live only for the run, like the one runTo sets, and one the
// user already has at an update function stays. Any other stop, such as the
// end of a replay, is not a screen update.
bool VMSession::runToScreenUpdate(bool backwards, const std::vector<uint64_t>& addresses) {
    const std::vector<uint64_t> added = addBreakpointsAt(addresses);
    beforeTargetRuns();
    const smalldbg::Status started = backwards ? debugger().reverseResume() : debugger().resume();
    const bool stopped = started == smalldbg::Status::Ok
        && debugger().waitForEvent(smalldbg::StopReason::None, kRunToTimeoutMs)
           != smalldbg::StopReason::None;
    afterTargetStops();
    for (uint64_t address : added) debugger().clearBreakpoint(address);
    return stopped && atScreenUpdate(addresses);
}

static bool hasBreakpointAt(const std::vector<smalldbg::Breakpoint>& breakpoints,
                            uint64_t address) {
    return std::any_of(breakpoints.begin(), breakpoints.end(),
                       [address](const smalldbg::Breakpoint& b) { return b.addr == address; });
}

std::vector<uint64_t> VMSession::addBreakpointsAt(const std::vector<uint64_t>& addresses) {
    const std::vector<smalldbg::Breakpoint> existing = debugger().listBreakpoints();
    std::vector<uint64_t> added;
    for (uint64_t address : addresses)
        if (!hasBreakpointAt(existing, address)
            && debugger().setBreakpoint(address, "screen update") == smalldbg::Status::Ok)
            added.push_back(address);
    return added;
}

// The VM calls these once a frame is drawn, so the target stops with the
// framebuffer whole rather than half drawn. A VM puts its screen in the window
// more often than the picture changes, such as once per changed rectangle, so
// updates that show the picture the target started on are passed over.
bool VMSession::runToFrame(bool backwards) {
    const std::vector<uint64_t> addresses = screenUpdateAddresses();
    if (addresses.empty()) return false;

    const std::optional<Framebuffer> start = inspector().framebuffer();
    bool reached = false;
    for (int run = 0; run < kMaxSameFrames; run++) {
        reached = runToScreenUpdate(backwards, addresses);
        if (!reached || !start) break;
        const std::optional<Framebuffer> now = inspector().framebuffer();
        if (!now || now->pixels != start->pixels) break;
    }
    return reached;
}

// Between two screen updates the framebuffer may hold a picture being drawn,
// such as the background a redraw clears to before drawing over it. What the
// screen showed then is what the VM last put in its window, so a replay is run
// back to that update, read there, and returned to where it was.
std::optional<Framebuffer> VMSession::shownFramebuffer() {
    const std::vector<uint64_t> addresses = screenUpdateAddresses();
    const std::optional<smalldbg::TracePosition> here = debugger().tracePosition();
    if (!here || addresses.empty() || atScreenUpdate(addresses)) return inspector().framebuffer();

    std::optional<Framebuffer> shown;
    if (runToScreenUpdate(true, addresses)) shown = inspector().framebuffer();
    seekTrace(*here);
    return shown ? shown : inspector().framebuffer();
}

bool VMSession::atScreenUpdate(const std::vector<uint64_t>& addresses) const {
    auto thread = debugger().getCurrentThread();
    if (!thread) return false;
    const uint64_t ip = thread->getInstructionPointer();
    return std::find(addresses.begin(), addresses.end(), ip) != addresses.end();
}

bool VMSession::runToNextFrame() { return runToFrame(false); }

bool VMSession::reverseRunToPreviousFrame() { return runToFrame(true); }

// A replay that moves runs nothing, so what was read from it is dropped
// rather than prepared for a run.
bool VMSession::seekTrace(const smalldbg::TracePosition& position) {
    bool moved = debugger().seekTrace(position) == smalldbg::Status::Ok;
    targetMayHaveMoved();
    return moved;
}

bool VMSession::seekTrace(double percent) {
    bool moved = debugger().seekTrace(percent) == smalldbg::Status::Ok;
    targetMayHaveMoved();
    return moved;
}

bool VMSession::setBreakpoint(uint64_t address, const std::string& name) {
    return debugger().setBreakpoint(address, name) == smalldbg::Status::Ok;
}

bool VMSession::clearBreakpoint(uint64_t address) {
    return debugger().clearBreakpoint(address) == smalldbg::Status::Ok;
}

} // namespace vmdbg
