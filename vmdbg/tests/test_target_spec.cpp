#include <doctest/doctest.h>

#include "Target.h"

#include <smalldbg/Debugger.h>

using vmdbg::TargetKind;

TEST_CASE("a path's extension names the kind of target") {
    CHECK(vmdbg::targetKindFor("C:/traces/vm.run") == TargetKind::Trace);
    CHECK(vmdbg::targetKindFor("crash.dmp") == TargetKind::Dump);
    CHECK(vmdbg::targetKindFor("vm.exe") == TargetKind::Launch);
    CHECK(vmdbg::targetKindFor("run") == TargetKind::Launch);
}

TEST_CASE("only dumps and traces are recorded, and only a trace replays") {
    CHECK(vmdbg::isRecordedTarget(TargetKind::Dump));
    CHECK(vmdbg::isRecordedTarget(TargetKind::Trace));
    CHECK_FALSE(vmdbg::isRecordedTarget(TargetKind::Launch));
    CHECK_FALSE(vmdbg::isRecordedTarget(TargetKind::Attach));

    CHECK(vmdbg::debuggeeFor(TargetKind::Trace) == smalldbg::Debuggee::Trace);
    CHECK(vmdbg::debuggeeFor(TargetKind::Dump) == smalldbg::Debuggee::Process);
    CHECK(vmdbg::debuggeeFor(TargetKind::Launch) == smalldbg::Debuggee::Process);
}

TEST_CASE("a trace does not open in a debugger built for a process") {
    smalldbg::Debugger dbg(smalldbg::Mode::External);
    vmdbg::TargetSpec trace;
    trace.kind = TargetKind::Trace;
    trace.path = "missing.run";
    CHECK(vmdbg::openInEngine(dbg, trace) == smalldbg::Status::NotSupported);
}
