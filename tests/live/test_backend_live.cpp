// End-to-end "live" backend tests: launch the instrumented test_target under
// the debugger and exercise the real backend (DbgEng/WinAPI) deterministically.
//
// Design notes:
//  * After launch() the backend is already stopped at the initial (loader)
//    breakpoint, so we inspect state there and never resume into interactive
//    input. The single run-control test resumes straight to process exit.
//  * test_target is launched with no arguments, so it never enters the stdin
//    "wait" mode and always runs to completion on its own.
#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"

#include "util.h"

using namespace smalldbg;

namespace {

// Launch test_target and return a debugger already stopped at the initial
// breakpoint. On failure the returned debugger is not attached.
void launchAtInitialStop(Debugger& dbg) {
    REQUIRE(dbg.launch(test::testTargetPath()) == Status::Ok);
    // initSession() leaves the backend stopped at the loader breakpoint.
    StopReason reason = dbg.waitForEvent(StopReason::None, 5000);
    REQUIRE(reason != StopReason::None);
    REQUIRE(dbg.isStopped());
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
    CHECK(r.arch == X64::instance());
    CHECK(r.ip() != 0);
    CHECK(r.sp() != 0);
    // Stack pointer is at least 8-byte aligned on x64.
    CHECK((r.sp() & 0x7) == 0);

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

TEST_CASE("stack unwinds to at least one frame at the initial stop") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    auto process = dbg.getProcess();
    REQUIRE(process.get() != nullptr);
    auto thread = process->primaryThread();
    REQUIRE(thread.get() != nullptr);

    StackTrace trace(thread.get());
    REQUIRE(trace.unwind() == Status::Ok);

    const auto& frames = trace.getFrames();
    REQUIRE(frames.size() > 0);
    CHECK(frames[0]->ip() != 0);

    dbg.detach();
}

TEST_CASE("resuming runs the target to a clean exit") {
    Debugger dbg(Mode::External, X64::instance());
    launchAtInitialStop(dbg);

    REQUIRE(dbg.resume() == Status::Ok);
    StopReason reason = dbg.waitForEvent(StopReason::ProcessExit, 15000);
    CHECK(reason == StopReason::ProcessExit);
}
