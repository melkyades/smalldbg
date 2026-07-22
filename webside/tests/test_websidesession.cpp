#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "WebsideSession.h"
#include "DisconnectedSession.h"
#include "smalldbg/StackTrace.h"

#include <memory>

using namespace webside;

namespace {
// Exposes the protected frame-formatting hooks for direct testing.
struct HookProbe : DisconnectedSession {
    using WebsideSession::buildFrameLabel;
    using WebsideSession::buildFrameDetailJson;
    using WebsideSession::buildFrameBindingsJson;
    using WebsideSession::buildFrameRegistersJson;
};
}

TEST_CASE("a disconnected session reports no active target") {
    DisconnectedSession session;

    CHECK_FALSE(session.isActive());
    CHECK_FALSE(session.getPid().has_value());
    CHECK(session.getDebugger() == nullptr);
}

TEST_CASE("a disconnected session ignores debug requests safely") {
    DisconnectedSession session;

    CHECK_FALSE(session.launch("some-target"));
    CHECK_FALSE(session.attach(1234));
    session.detach();  // no-op — must not crash
}

TEST_CASE("a disconnected session refuses run control and reports empty state") {
    DisconnectedSession session;

    CHECK_FALSE(session.resume());
    CHECK_FALSE(session.suspend());
    CHECK_FALSE(session.step());
    CHECK_FALSE(session.stepOver());
    CHECK_FALSE(session.stepOver(0));
    CHECK_FALSE(session.stepOut());
    CHECK_FALSE(session.stepBack());
    CHECK_FALSE(session.reverseStepOver());
    CHECK_FALSE(session.reverseStepOut());

    CHECK(session.getStopReason().empty());
    CHECK(session.getRegisters() == "{}");
}

TEST_CASE("frame label combines module and function") {
    HookProbe s;

    smalldbg::StackFrame both;
    both.moduleName = "kernel32";
    both.functionName = "DoStuff";
    CHECK(s.buildFrameLabel(both) == "kernel32!DoStuff");

    smalldbg::StackFrame funcOnly;
    funcOnly.functionName = "onlyFunc";
    CHECK(s.buildFrameLabel(funcOnly) == "onlyFunc");

    smalldbg::StackFrame unknown;
    CHECK(s.buildFrameLabel(unknown) == "<unknown>");
}

TEST_CASE("frame detail JSON distinguishes native and VM frames") {
    HookProbe s;

    smalldbg::StackFrame nativeFrame;
    nativeFrame.moduleName = "kernel32";
    nativeFrame.functionName = "DoStuff";
    const std::string nativeJson = s.buildFrameDetailJson(nativeFrame, 1);
    CHECK(nativeJson.find("kernel32!DoStuff") != std::string::npos);
    CHECK(nativeJson.find("native") != std::string::npos);

    smalldbg::StackFrame vmFrame;
    vmFrame.moduleName = "Integer";
    vmFrame.functionName = "+";
    vmFrame.metadata = std::make_unique<smalldbg::FrameMetadata>();
    const std::string vmJson = s.buildFrameDetailJson(vmFrame, 2);
    CHECK(vmJson.find("vm") != std::string::npos);
}

TEST_CASE("native frame bindings expose IP/FP/SP") {
    HookProbe s;
    smalldbg::StackFrame f;
    f.registers.x64.rip = 0x1000;

    const std::string json = s.buildFrameBindingsJson(f, 0);
    CHECK(json.find("\"IP\"") != std::string::npos);
    CHECK(json.find("\"FP\"") != std::string::npos);
    CHECK(json.find("\"SP\"") != std::string::npos);
    CHECK(json.find("1000") != std::string::npos);  // IP value
}

TEST_CASE("frame registers JSON reflects the x64 register set") {
    HookProbe s;
    smalldbg::StackFrame f;  // arch defaults to x64
    f.registers.x64.rax = 0xdead;

    const std::string json = s.buildFrameRegistersJson(f);
    CHECK(json.find("\"rip\"") != std::string::npos);
    CHECK(json.find("\"rax\"") != std::string::npos);
    CHECK(json.find("dead") != std::string::npos);
}
