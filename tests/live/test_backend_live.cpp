// End-to-end "live" backend tests: launch the instrumented test_target under
// the debugger and exercise the real backend (DbgEng/WinAPI) deterministically.
//
// Design notes:
//  * After launch() the backend is already stopped at the initial (loader)
//    breakpoint, so we inspect state there and never resume into interactive
//    input. The single run-control test resumes straight to process exit.
//  * test_target is launched with no arguments, so it never enters the stdin
//    "wait" mode and always runs to completion on its own.
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolLoader.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include "util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace smalldbg;

namespace {

// Sends the backend's log to stderr when SMALLDBG_TEST_LOG is set.
void logWhenAsked(Debugger& dbg) {
    if (std::getenv("SMALLDBG_TEST_LOG")) {
        dbg.setLogCallback([](const std::string& m){ fprintf(stderr, "LOG %s\n", m.c_str()); });
    }
}

// Launch test_target and return a debugger already stopped at the initial
// breakpoint. On failure the returned debugger is not attached.
void launchAtInitialStop(Debugger& dbg, const std::vector<std::string>& args = {}) {
    logWhenAsked(dbg);
    REQUIRE(dbg.launch(test::testTargetPath(), args) == Status::Ok);
    // initSession() leaves the backend stopped at the loader breakpoint.
    StopReason reason = dbg.waitForEvent(StopReason::None, 5000);
    REQUIRE(reason != StopReason::None);
    REQUIRE(dbg.isStopped());
}

// Launch test_target, run it to the "break_here" breakpoint, and return the
// resolved symbol. Startup module loads intervene between the loader stop
// and user code, so tests that need real code (e.g. single-stepping) must
// reach this point first rather than stepping from the loader breakpoint.
Symbol launchAtBreakHere(Debugger& dbg, const std::vector<std::string>& args = {}) {
    launchAtInitialStop(dbg, args);

    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    auto sym = symbols->getSymbolByName("test_target!break_here");
    REQUIRE(sym.has_value());
    REQUIRE(sym->address != 0);

    REQUIRE(dbg.setBreakpoint(sym->address, "break_here") == Status::Ok);

    REQUIRE(dbg.resume() == Status::Ok);
    StopReason reason = dbg.waitForEvent(StopReason::Breakpoint, 15000);
    REQUIRE(reason == StopReason::Breakpoint);

    return *sym;
}

// Where the current frame returns to in its caller.
Address callerResumeAddress(Debugger& dbg) {
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);
    StackTrace trace(thread.get());
    REQUIRE(trace.unwind(2) == Status::Ok);
    REQUIRE(trace.getFrameCount() >= 2);
    return trace.getFrames()[1]->ip();
}

Address currentIP(Debugger& dbg) {
    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);
    return r.ip();
}

// The instruction the target is stopped on.
DisasmInsn currentInstruction(Debugger& dbg) {
    Address ip = currentIP(dbg);
    uint8_t code[16];
    REQUIRE(dbg.readMemory(ip, code, sizeof code) == Status::Ok);
    auto insns = dbg.getDisassembler()->disassemble(code, sizeof code, ip);
    REQUIRE_FALSE(insns.empty());
    return insns[0];
}

// Single-step until the target is stopped on a call; false if none comes
// within `limit` steps.
bool stepToCall(Debugger& dbg, int limit) {
    for (int i = 0; i < limit; i++) {
        if (currentInstruction(dbg).isCall) return true;
        REQUIRE(dbg.step() == Status::Ok);
        REQUIRE(dbg.waitForEvent(StopReason::SingleStep, 15000) == StopReason::SingleStep);
    }
    return false;
}

} // namespace

TEST_CASE("launch attaches and stops at the initial breakpoint") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    CHECK(dbg.isAttached());
    auto pid = dbg.attachedPid();
    REQUIRE(pid.has_value());
    CHECK(pid.value() != 0);

    CHECK(dbg.detach() == Status::Ok);
    CHECK_FALSE(dbg.isAttached());
}

TEST_CASE("registers are readable and sane at the initial stop") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);
    CHECK(r.arch == dbg.arch());
    CHECK(r.ip() != 0);
    CHECK(r.sp() != 0);
    CHECK(r.sp() % r.pointerSize() == 0);

    dbg.detach();
}

TEST_CASE("memory can be read from the target stack") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);

    uint8_t buffer[32] = {};
    CHECK(dbg.readMemory(r.sp(), buffer, sizeof(buffer)) == Status::Ok);

    dbg.detach();
}

TEST_CASE("breakpoints can be set, listed and cleared") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);
    const Address addr = r.ip();

    const size_t before = dbg.listBreakpoints().size();
    REQUIRE(dbg.setBreakpoint(addr, "probe") == Status::Ok);

    auto bps = dbg.listBreakpoints();
    CHECK(bps.size() == before + 1);
    bool found = false;
    for (const auto& bp : bps)
        if (bp.addr == addr && bp.name == "probe") found = true;
    CHECK(found);

    REQUIRE(dbg.clearBreakpoint(addr) == Status::Ok);
    CHECK(dbg.listBreakpoints().size() == before);

    dbg.detach();
}

TEST_CASE("a symbol search path that is set is searched first") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    const std::string dir = std::filesystem::temp_directory_path().string();
    symbols->setSearchPath(dir);
    CHECK(symbols->searchPath().rfind(dir, 0) == 0);

    dbg.detach();
}

TEST_CASE("a module's symbols load on request, and any spelling finds it") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    CHECK(symbols->loadModuleSymbols("test_target"));
    CHECK(symbols->moduleNamed("TEST_TARGET.exe").hasSymbolFile());

    CHECK(symbols->moduleNamed("no_such_module").shortName.empty());
    CHECK_FALSE(symbols->loadModuleSymbols("no_such_module"));

    dbg.detach();
}

TEST_CASE("the symbol loader loads a module's own symbol file and says which") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    std::vector<std::string> log;
    SymbolLoader loader(dbg, [&](const std::string& line) { log.push_back(line); });

    CHECK(loader.loadAndReport("test_target"));
    REQUIRE_FALSE(log.empty());
    CHECK(log.back().find("test_target.pdb") != std::string::npos);

    CHECK(loader.load("no_such_module") == SymbolState::Missing);
    CHECK_FALSE(loader.report("no_such_module", SymbolState::Missing, "needed for X"));
    CHECK(std::find(log.begin(), log.end(), "needed for X") != log.end());

    dbg.detach();
}

TEST_CASE("a name without its module is found only where symbols are loaded") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);
    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);

    CHECK_FALSE(symbols->getSymbolByName("break_here").has_value());
    CHECK(symbols->getSymbolByName("test_target!break_here").has_value());
    CHECK(symbols->getSymbolByName("break_here").has_value());

    bool found = false;
    for (const auto& symbol : symbols->findSymbols("break_her*"))
        if (symbol.name == "break_here") found = true;
    CHECK(found);

    dbg.detach();
}

TEST_CASE("a preferred module is searched for a name without one") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);
    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);

    symbols->preferModule("test_target");
    CHECK(symbols->getSymbolByName("break_here").has_value());

    dbg.detach();
}

TEST_CASE("an address inside a function is named, and its size given on request") {
    Debugger dbg(Mode::External, X64::instance());
    Symbol breakHere = launchAtBreakHere(dbg);
    auto* symbols = dbg.getSymbolProvider();

    auto sized = symbols->getSymbolWithExtent(breakHere.address);
    REQUIRE(sized.has_value());
    REQUIRE(sized->size > 1);

    auto inside = symbols->symbolicInfoFor(breakHere.address + 1);
    REQUIRE(inside.has_value());
    CHECK(inside->name == "break_here");

    dbg.detach();
}

TEST_CASE("a global's type and that type's fields come from the pdb") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    auto* symbols = dbg.getSymbolProvider();

    auto typeName = symbols->getVariableTypeName("test_target!g_test_record");
    REQUIRE(typeName.has_value());
    CHECK(typeName->find("TestRecord") != std::string::npos);

    const NativeTypeInfo* type = symbols->getTypeByName(*typeName);
    REQUIRE(type != nullptr);
    CHECK(type->kind == NativeTypeKind::Struct);
    REQUIRE(type->fields.size() == 3);
    CHECK(type->fields[0].name == "id");
    CHECK(type->fields[1].name == "weight");
    CHECK(type->fields[1].offset == 8);
    CHECK(type->fields[2].name == "label");
    CHECK(type->fields[2].offset == 16);

    CHECK(symbols->getTypeByName("test_target!NoSuchType") == nullptr);
    CHECK(symbols->getTypeByName("test_target!NoSuchType") == nullptr);

    dbg.detach();
}

TEST_CASE("an address inside a global struct is named by its field") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    auto* symbols = dbg.getSymbolProvider();

    auto record = symbols->getSymbolByName("test_target!g_test_record");
    REQUIRE(record.has_value());

    auto weight = symbols->getFieldAt(record->address + 8);
    REQUIRE(weight.has_value());
    CHECK(weight->name == "weight");
    CHECK(weight->start == record->address + 8);
    CHECK(weight->size == 8);
    CHECK(weight->owner.find("TestRecord") != std::string::npos);

    auto inside = symbols->getFieldAt(record->address + 12);
    REQUIRE(inside.has_value());
    CHECK(inside->name == "weight");
    CHECK(symbols->getFieldAt(record->address + 16)->name == "label");
    CHECK(symbols->getFieldAt(record->address)->name == "id");

    auto breakHere = symbols->getSymbolByName("test_target!break_here");
    REQUIRE(breakHere.has_value());
    CHECK_FALSE(symbols->getFieldAt(breakHere->address).has_value());

    auto typeName = symbols->getVariableTypeName("test_target!g_test_record");
    REQUIRE(typeName.has_value());
    CHECK(symbols->getStructType(*typeName) != nullptr);
    CHECK(symbols->getStructType("test_target!NoSuchType") == nullptr);

    dbg.detach();
}

TEST_CASE("running to an address stops there and keeps the user's breakpoints") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);
    auto breakHere = dbg.getSymbolProvider()->getSymbolByName(
        "test_target!break_here");
    REQUIRE(breakHere.has_value());

    REQUIRE(dbg.runTo(breakHere->address, 30000) == Status::Ok);
    Registers regs;
    REQUIRE(dbg.getRegisters(regs) == Status::Ok);
    CHECK(regs.ip() == breakHere->address);
    CHECK(dbg.listBreakpoints().empty());

    // At a function's first instruction the stack pointer points at the
    // return address.
    Address returnAddress = 0;
    REQUIRE(dbg.readMemory(regs.sp(), &returnAddress,
                           dbg.arch()->pointerSize()) == Status::Ok);
    REQUIRE(dbg.setBreakpoint(returnAddress, "mine") == Status::Ok);
    REQUIRE(dbg.runTo(returnAddress, 30000) == Status::Ok);
    REQUIRE(dbg.listBreakpoints().size() == 1);
    CHECK(dbg.listBreakpoints()[0].addr == returnAddress);

    dbg.detach();
}

TEST_CASE("a thread is named after what it was started to do") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread != nullptr);

    const ThreadIdentity& identity = dbg.threadIdentity(*thread);
    CHECK(identity.hasContext);
    CHECK(identity.name.rfind("test_target!", 0) == 0);
    CHECK(&dbg.threadIdentity(*thread) == &identity);

    dbg.detach();
}

TEST_CASE("stack unwinds to at least one frame at the initial stop") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    auto process = dbg.getProcess();
    REQUIRE(process.get() != nullptr);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    StackTrace trace(thread.get());
    REQUIRE(trace.unwind() == Status::Ok);

    const auto& frames = trace.getFrames();
    REQUIRE(frames.size() > 0);
    CHECK(frames[0]->ip() != 0);

    dbg.detach();
}

// test_target's "deep" mode recurses 30 times before calling break_here, so a
// stack walk that stops early fails the frame count.
TEST_CASE("a deep stack unwinds all the way to the thread start") {
    Debugger dbg(Mode::External, X64::instance());

    REQUIRE(dbg.launch(test::testTargetPath(), {"deep"}) == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 5000) != StopReason::None);

    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    auto breakHere = symbols->getSymbolByName("test_target!break_here");
    REQUIRE(breakHere.has_value());
    REQUIRE(dbg.setBreakpoint(breakHere->address, "break_here") == Status::Ok);
    REQUIRE(dbg.resume() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::Breakpoint, 20000) == StopReason::Breakpoint);

    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    StackTrace trace(thread.get());
    REQUIRE(trace.unwind(256) == Status::Ok);
    const auto& frames = trace.getFrames();

    // 30 recursions, plus break_here, main and whatever started the thread.
    CHECK(frames.size() > 30);

    bool reachedThreadStart = false;
    for (const auto& frame : frames)
        if (frame->functionName.find("RtlUserThreadStart") != std::string::npos)
            reachedThreadStart = true;
    CHECK(reachedThreadStart);

    dbg.detach();
}

TEST_CASE("a thread keeps its stack trace until the target moves") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    StackTrace* trace = thread->getStackTrace(16);
    REQUIRE(trace != nullptr);
    CHECK(thread->getStackTrace(16) == trace);
    CHECK(thread->getStackTrace(4) == trace);

    StackTrace* deeper = thread->getStackTrace(64);
    REQUIRE(deeper != nullptr);
    CHECK(deeper != trace);

    REQUIRE(dbg.step() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::SingleStep, 15000) == StopReason::SingleStep);
    StackTrace* moved = thread->getStackTrace(64);
    REQUIRE(moved != nullptr);
    CHECK(moved != deeper);

    dbg.detach();
}

// A process attached to has loaded its modules already, and the engine hears
// of them only from the events queued behind the attach's first one.
TEST_CASE("attaching to a running process finds the modules it already loaded") {
    test::WaitingTarget target;
    REQUIRE(target.pid() != 0);

    Debugger dbg(Mode::External, X64::instance());
    logWhenAsked(dbg);
    REQUIRE(dbg.attach(target.pid()) == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 5000) != StopReason::None);

    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    CHECK(symbols->getSymbolByName("kernel32!CreateFileW").has_value());

    dbg.detach();
    target.release();
    CHECK(target.waitForExit(5000) == 0);
}

// test_target's "deep" mode keeps running while a debugger holds it, which
// gives a suspend something to stop. It is done several times over, as a
// break-in that is not matched by a resume leaves the target suspended.
TEST_CASE("suspending a running target stops it, every time") {
    Debugger dbg(Mode::External, X64::instance());
    logWhenAsked(dbg);
    REQUIRE(dbg.launch(test::testTargetPath(), {"deep"}) == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 5000) != StopReason::None);

    for (int i = 0; i < 5; ++i) {
        REQUIRE(dbg.resume() == Status::Ok);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        REQUIRE(dbg.suspend() == Status::Ok);
        REQUIRE(dbg.isStopped());
        Registers r;
        CHECK(dbg.getRegisters(r) == Status::Ok);
    }

    dbg.detach();
}

// The engine thread serves one caller at a time; another caller is told the
// engine is busy rather than left waiting behind the first.
TEST_CASE("a caller is refused while another waits on the engine") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    std::thread slow([&] { dbg.executeCommand(".sleep 250"); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Registers r;
    CHECK(dbg.getRegisters(r) == Status::Busy);
    slow.join();
    CHECK(dbg.getRegisters(r) == Status::Ok);

    dbg.detach();
}

// test_target's "crash" mode throws a C++ exception nothing catches. The
// target stops on it, says which exception it was, and resuming then lets the
// process end.
TEST_CASE("an unhandled exception stops the target") {
    Debugger dbg(Mode::External, X64::instance());
    logWhenAsked(dbg);
    REQUIRE(dbg.launch(test::testTargetPath(), {"crash"}) == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 5000) != StopReason::None);

    REQUIRE(dbg.resume() == Status::Ok);
    CHECK(dbg.waitForEvent(StopReason::Exception, 15000) == StopReason::Exception);
    auto exception = dbg.getStopException();
    REQUIRE(exception.has_value());
    CHECK(exception->code == 0xE06D7363);  // the code every C++ throw raises
    CHECK(exception->address != 0);

    REQUIRE(dbg.resume() == Status::Ok);
    CHECK(dbg.waitForEvent(StopReason::ProcessExit, 15000) == StopReason::ProcessExit);
    CHECK_FALSE(dbg.getStopException().has_value());
}

// The engine is shared by every debugger in a process. One whose target ran to
// its end must close its session with it, or the next debugger reads through
// the old one.
TEST_CASE("a debugger whose target exited leaves the engine to the next one") {
    {
        Debugger first(Mode::External, X64::instance());
        launchAtInitialStop(first);
        REQUIRE(first.resume() == Status::Ok);
        REQUIRE(first.waitForEvent(StopReason::ProcessExit, 15000) == StopReason::ProcessExit);
    }

    Debugger second(Mode::External, X64::instance());
    launchAtInitialStop(second);
    Registers r;
    REQUIRE(second.getRegisters(r) == Status::Ok);
    uint8_t buffer[32] = {};
    CHECK(second.readMemory(r.sp(), buffer, sizeof(buffer)) == Status::Ok);

    second.detach();
}

// test_target's "threads" mode starts threads that end before break_here.
// Once refreshed, the thread list holds only threads the target still has,
// each of which can be read.
TEST_CASE("refreshing the thread list drops threads that have ended") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg, {"threads"});

    dbg.refreshThreads();
    auto threads = dbg.getProcess()->threads();
    REQUIRE_FALSE(threads.empty());
    for (const auto& thread : threads) {
        Registers r;
        CHECK(dbg.getRegisters(thread.get(), r) == Status::Ok);
    }

    dbg.detach();
}

// Reading the target leaves the state version alone; moving it changes it.
TEST_CASE("the state version changes when the target moves, not when it is read") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);
    uint64_t before = dbg.stateVersion();

    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);
    uint8_t byte = 0;
    CHECK(dbg.readMemory(r.sp(), &byte, 1) == Status::Ok);
    CHECK(dbg.stateVersion() == before);

    REQUIRE(dbg.step() == Status::Ok);
    CHECK(dbg.stateVersion() != before);

    dbg.detach();
}

TEST_CASE("resuming runs the target to a clean exit") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    REQUIRE(dbg.resume() == Status::Ok);
    StopReason reason = dbg.waitForEvent(StopReason::ProcessExit, 15000);
    CHECK(reason == StopReason::ProcessExit);
}

TEST_CASE("a breakpoint on a known function is hit when the target runs") {
    Debugger dbg(Mode::External, X64::instance());
    Symbol sym = launchAtBreakHere(dbg);

    // The stop address should be at (or within) the break_here function.
    Registers r;
    REQUIRE(dbg.getRegisters(r) == Status::Ok);
    CHECK(r.ip() >= sym.address);
    CHECK(r.ip() < sym.address + (sym.size ? sym.size : 64));
    CHECK_FALSE(dbg.getStopException().has_value());

    dbg.detach();
}

TEST_CASE("single-stepping advances the instruction pointer") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);

    Registers before;
    REQUIRE(dbg.getRegisters(before) == Status::Ok);

    REQUIRE(dbg.step() == Status::Ok);
    StopReason reason = dbg.waitForEvent(StopReason::SingleStep, 15000);
    REQUIRE(reason == StopReason::SingleStep);

    Registers after;
    REQUIRE(dbg.getRegisters(after) == Status::Ok);
    CHECK(after.ip() != before.ip());

    dbg.detach();
}

TEST_CASE("stepping out of a function stops where its caller resumes") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    Address resumeAt = callerResumeAddress(dbg);

    REQUIRE(dbg.stepOut() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 15000) != StopReason::None);
    CHECK(currentIP(dbg) == resumeAt);

    dbg.detach();
}

TEST_CASE("stepping over a call stops at the instruction after it") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    REQUIRE(dbg.stepOut() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 15000) != StopReason::None);

    REQUIRE(stepToCall(dbg, 200));
    DisasmInsn call = currentInstruction(dbg);

    REQUIRE(dbg.stepOver() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 15000) != StopReason::None);
    CHECK(currentIP(dbg) == call.address + call.size);

    dbg.detach();
}

TEST_CASE("stepping over an instruction that is not a call is a single step") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtBreakHere(dbg);
    DisasmInsn first = currentInstruction(dbg);
    REQUIRE_FALSE(first.isCall);

    REQUIRE(dbg.stepOver() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 15000) != StopReason::None);
    CHECK(currentIP(dbg) == first.address + first.size);

    dbg.detach();
}
