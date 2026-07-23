#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "WebsideSession.h"
#include "DisconnectedSession.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Thread.h"

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

TEST_CASE("a disconnected session has no green threads") {
    DisconnectedSession session;

    session.refreshGreenThreads();  // no-op — must not crash
    CHECK(session.greenThreadCount() == 0);
    CHECK(session.getGreenThreadName(0).empty());
    CHECK(session.listSmalltalkFrames(0) == "[]");
    CHECK(session.getSmalltalkFrameDetail(0, 0) == "{}");
    CHECK(session.getSmalltalkFrameBindings(0, 0) == "[]");
}

TEST_CASE("a disconnected session exposes no classes") {
    DisconnectedSession session;

    CHECK_FALSE(session.discoverClasses());
    CHECK(session.listClasses("", false, false, -1) == "[]");
    CHECK(session.getClass("Object") == "{}");
    CHECK(session.getMethods("Object") == "[]");
    CHECK(session.search("x", false, "", "") == "[]");
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

// Minimal concrete session backed by a real Debugger, for the live frame-API
// test. Only the members the frame API needs are meaningful; the rest are
// interface stubs.
namespace {
struct LiveSession : WebsideSession {
    std::unique_ptr<smalldbg::Debugger> dbg;

    bool launch(const std::string& target, const std::vector<std::string>& = {}) override {
        dbg = std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External, smalldbg::X64::instance());
        return dbg->launch(target) == smalldbg::Status::Ok;
    }
    bool isActive() const override { return dbg && dbg->isAttached(); }
    smalldbg::Debugger* getDebugger() const override { return dbg.get(); }

    bool attach(int) override { return false; }
    void detach() override { if (dbg) dbg->detach(); }
    std::optional<int> getPid() const override { return std::nullopt; }
    bool resume() override { return false; }
    bool suspend() override { return false; }
    bool step() override { return false; }
    bool stepOver() override { return false; }
    bool stepOver(int) override { return false; }
    bool stepOut() override { return false; }
    bool stepBack() override { return false; }
    bool reverseStepOver() override { return false; }
    bool reverseStepOut() override { return false; }
    std::string getStopReason() const override { return ""; }
    std::string getRegisters() const override { return "{}"; }
    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return ""; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override { return "{}"; }
    std::string getSmalltalkFrameBindings(int, int) const override { return "[]"; }
    bool discoverClasses() override { return false; }
    std::string listClasses(const std::string&, bool, bool, int) const override { return "[]"; }
    std::string getClass(const std::string&) const override { return "{}"; }
    std::string getSubclasses(const std::string&) const override { return "[]"; }
    std::string getSuperclasses(const std::string&) const override { return "[]"; }
    std::string getVariables(const std::string&) const override { return "[]"; }
    std::string getInstanceVariables(const std::string&) const override { return "[]"; }
    std::string getClassVariables(const std::string&) const override { return "[]"; }
    std::string getCategories(const std::string&) const override { return "[]"; }
    std::string getUsedCategories(const std::string&) const override { return "[]"; }
    std::string getSelectors(const std::string&) const override { return "[]"; }
    std::string getMethods(const std::string&) const override { return "[]"; }
    std::string getMethod(const std::string&, const std::string&) const override { return "{}"; }
    std::string search(const std::string&, bool, const std::string&, const std::string&) const override { return "[]"; }
};
}

TEST_CASE("listFrames returns real frames for a launched target") {
    LiveSession s;
    REQUIRE(s.launch(WEBSIDE_TEST_TARGET));
    REQUIRE(s.getDebugger()->waitForEvent(smalldbg::StopReason::None, 5000) != smalldbg::StopReason::None);

    auto thread = s.primaryThread();
    REQUIRE(thread);

    const std::string json = s.listFrames(*thread);
    CHECK(json != "[]");
    CHECK(json.find("\"index\"") != std::string::npos);
    CHECK(json.find("\"label\"") != std::string::npos);

    s.getDebugger()->detach();
}
