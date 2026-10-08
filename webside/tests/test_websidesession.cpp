#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "WebsideSession.h"
#include "VMInspector.h"
#include "Workspace.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Thread.h"

#include <map>
#include <memory>

using namespace webside;

namespace {

struct StubInspector : vmdbg::VMInspector {
    StackRegion evaluatorStack() const override { return {}; }
};

// Answers every query without a target behind it, so the parts of the session
// that do not read the debugger can be exercised on their own.
struct StubSession : WebsideSession {
    // Nothing is opened in an engine, so a target succeeds unless the test
    // named the one that must not.
    bool readsWithoutEngine(const TargetSpec&) const override { return true; }
    bool onTargetOpened(const TargetSpec& target) override {
        return target.path != "unopenable";
    }
    bool isActive() const override { return false; }
    std::optional<int> getPid() const override { return std::nullopt; }
    std::string getStopReason() const override { return ""; }
    std::string getRegisters() const override { return "{}"; }
    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return ""; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override { return "{}"; }
    std::string getSmalltalkFrameBindings(int, int) const override { return "[]"; }
    std::string getSmalltalkStackContents(int) const override { return "[]"; }
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
    std::string search(const std::string&, bool, const std::string&,
                       const std::string&) const override { return "[]"; }
    // The shared implementation would go to a debugger; this records instead,
    // which is what lets a test see what the workspace re-applied.
    bool setBreakpoint(uint64_t address, const std::string& name = "") override {
        applied[address] = name;
        return true;
    }
    bool clearBreakpoint(uint64_t address) override {
        return applied.erase(address) != 0;
    }
    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, size_t) const override { return "{}"; }
    std::shared_ptr<smalldbg::Thread> vmThread() const override { return nullptr; }
    smalldbg::Debugger& debugger() const override { return *ownedDebugger; }
    vmdbg::VMInspector& inspector() const override { return *ownedInspector; }

    // Never attached and never asked to inspect, but always there, so the
    // session can hand out the references its interface promises.
    const std::unique_ptr<smalldbg::Debugger> ownedDebugger{
        std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External)};
    const std::unique_ptr<vmdbg::VMInspector> ownedInspector{
        std::make_unique<StubInspector>()};

    std::map<uint64_t, std::string> applied;
};

// Exposes the protected frame-formatting hooks for direct testing.
struct HookProbe : StubSession {
    using WebsideSession::buildFrameLabel;
    using WebsideSession::buildFrameDetailJson;
    using WebsideSession::buildFrameBindingsJson;
    using WebsideSession::buildFrameRegistersJson;
};

// Opens a StubSession for any target whose path is not "unopenable".
struct StubWorkspace : Workspace {
    int opens{0};
    StubSession* last{nullptr};

    StubWorkspace()
        : Workspace([this](const TargetSpec&) -> std::unique_ptr<WebsideSession> {
              ++opens;
              auto created = std::make_unique<StubSession>();
              last = created.get();
              return created;
          }) {}
};

TargetSpec specFor(const std::string& path) {
    TargetSpec spec;
    spec.path = path;
    return spec;
}

} // namespace

TEST_CASE("a fresh workspace has nothing open") {
    StubWorkspace workspace;

    CHECK_FALSE(workspace.isConnected());
    CHECK(workspace.session() == nullptr);
}

TEST_CASE("opening a workspace gives it a session, closing takes it away") {
    StubWorkspace workspace;

    REQUIRE(workspace.open(specFor("target")));
    CHECK(workspace.isConnected());
    CHECK(workspace.session() != nullptr);
    CHECK(workspace.target().path == "target");

    workspace.close();
    CHECK_FALSE(workspace.isConnected());
    CHECK(workspace.session() == nullptr);
}

TEST_CASE("a target that will not open leaves the workspace disconnected") {
    StubWorkspace workspace;

    CHECK_FALSE(workspace.open(specFor("unopenable")));
    CHECK_FALSE(workspace.isConnected());
}

TEST_CASE("reopening builds a new session from the same target") {
    StubWorkspace workspace;

    REQUIRE(workspace.open(specFor("target")));

    // Reopening frees the old session before building the new one, so the
    // allocator hands back the same block often enough that comparing the two
    // addresses says nothing. What the factory last produced does.
    REQUIRE(workspace.reopen());
    CHECK(workspace.opens == 2);
    CHECK(workspace.session() == workspace.last);
    CHECK(workspace.target().path == "target");
}

TEST_CASE("breakpoints outlive the session they were set in") {
    StubWorkspace workspace;

    workspace.setBreakpoint(0x1000, "start");
    REQUIRE(workspace.open(specFor("target")));
    CHECK(workspace.last->applied.count(0x1000) == 1);

    workspace.setBreakpoint(0x2000, "later");
    CHECK(workspace.last->applied.count(0x2000) == 1);

    REQUIRE(workspace.reopen());
    CHECK(workspace.last->applied.size() == 2);

    workspace.clearBreakpoint(0x1000);
    CHECK(workspace.breakpoints().size() == 1);
    CHECK(workspace.last->applied.count(0x1000) == 0);
}

TEST_CASE("labels are the developer's own and belong to the workspace") {
    StubWorkspace workspace;

    workspace.setLabel(0x400000, "vmEntry");
    CHECK(workspace.labelAt(0x400000) == "vmEntry");
    CHECK(workspace.labelAt(0x400004).empty());

    REQUIRE(workspace.open(specFor("target")));
    workspace.close();
    CHECK(workspace.labelAt(0x400000) == "vmEntry");

    workspace.clearLabel(0x400000);
    CHECK(workspace.labels().empty());
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
    std::unique_ptr<smalldbg::Debugger> dbg{
        std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External, smalldbg::X64::instance())};

    struct NoInspector : vmdbg::VMInspector {
        StackRegion evaluatorStack() const override { return {}; }
    } noInspector;

    bool isActive() const override { return dbg->isAttached(); }
    smalldbg::Debugger& debugger() const override { return *dbg; }
    vmdbg::VMInspector& inspector() const override {
        return const_cast<NoInspector&>(noInspector);
    }
    // The target runs no VM; the thread it stopped on stands in for one.
    std::shared_ptr<smalldbg::Thread> vmThread() const override {
        return dbg->getCurrentThread();
    }
    bool onTargetOpened(const vmdbg::TargetSpec&) override { return true; }
    std::optional<int> getPid() const override { return std::nullopt; }
    std::string getStopReason() const override { return ""; }
    std::string getRegisters() const override { return "{}"; }
    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return ""; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override { return "{}"; }
    std::string getSmalltalkFrameBindings(int, int) const override { return "[]"; }
    std::string getSmalltalkStackContents(int) const override { return "[]"; }
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
    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, size_t) const override { return "{}"; }
};
}

TEST_CASE("listFrames returns real frames for a launched target") {
    LiveSession s;
    vmdbg::TargetSpec spec;
    spec.path = WEBSIDE_TEST_TARGET;
    REQUIRE(s.open(spec));
    REQUIRE(s.debugger().waitForEvent(smalldbg::StopReason::None, 5000) != smalldbg::StopReason::None);

    auto thread = s.vmThread();
    REQUIRE(thread);

    const std::string json = s.listFrames(*thread);
    CHECK(json != "[]");
    CHECK(json.find("\"index\"") != std::string::npos);
    CHECK(json.find("\"label\"") != std::string::npos);

    s.debugger().detach();
}
