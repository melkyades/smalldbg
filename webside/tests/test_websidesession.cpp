#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "Json.h"
#include "SourceExcerpt.h"
#include "StubSession.h"
#include "WebsideSession.h"
#include "Workspace.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Thread.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>

using namespace webside;

namespace {

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

// A source file with one function, whose second line is `line`.
std::string writeSource(const std::string& line) {
    auto path = (std::filesystem::temp_directory_path() / "smalldbg_excerpt.cpp").string();
    std::ofstream(path) << "#include <cstdio>\n"
                           "\n"
                           "int twice(int x)\n"
                           "{\n"
                           "    " << line << "\n"
                           "}\n";
    return path;
}

TEST_CASE("a source excerpt is the function around a line") {
    auto path = writeSource("return 2 * x;");
    auto excerpt = webside::functionAround(path, 5);
    REQUIRE(excerpt);
    CHECK(excerpt->text == "int twice(int x)\n{\n    return 2 * x;\n}");
    CHECK(excerpt->text.substr(excerpt->lineStart, excerpt->lineLength)
          == "    return 2 * x;");
    CHECK_FALSE(webside::functionAround(path, 1));
    CHECK_FALSE(webside::functionAround(path, 99));
    CHECK_FALSE(webside::functionAround("missing.cpp", 5));
    std::remove(path.c_str());
}

TEST_CASE("a native frame with a source line shows its function") {
    HookProbe s;
    smalldbg::StackFrame frame;
    frame.functionName = "twice";
    frame.sourceFile = writeSource("return 2 * x;");
    frame.sourceLine = 5;
    Json detail = Json::parse(s.buildFrameDetailJson(frame, 1));
    CHECK(detail["hasSource"].asBool());
    CHECK(detail["method"]["source"].asString().find("return 2 * x;")
          != std::string::npos);
    CHECK(detail["interval"]["start"].asInt() == 19);
    CHECK(detail["interval"]["end"].asInt() == 36);
    std::remove(frame.sourceFile.c_str());

    frame.sourceFile = "missing.cpp";
    detail = Json::parse(s.buildFrameDetailJson(frame, 1));
    CHECK_FALSE(detail["hasSource"].asBool());
    CHECK(detail["interval"]["end"].asInt() == 0);
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
    f.allRegisters = true;

    const std::string json = s.buildFrameRegistersJson(f);
    CHECK(json.find("\"rip\"") != std::string::npos);
    CHECK(json.find("\"rax\"") != std::string::npos);
    CHECK(json.find("dead") != std::string::npos);
}

TEST_CASE("a caller's registers other than ip, sp and fp are null") {
    HookProbe s;
    smalldbg::StackFrame f;
    f.registers.x64.rax = 0xdead;
    f.registers.x64.rbp = 0x3000;

    Json regs = Json::parse(s.buildFrameRegistersJson(f));
    CHECK(regs[2]["name"].asString() == "rbp");
    CHECK(regs[2]["value"].isString());
    CHECK(regs[3]["name"].asString() == "rax");
    CHECK(regs[3]["value"].isNull());
}

TEST_CASE("listFrames returns real frames for a launched target") {
    LiveSession s;
    vmdbg::TargetSpec spec;
    spec.path = WEBSIDE_TEST_TARGET;
    REQUIRE(s.open(spec));
    REQUIRE(s.debugger().waitForEvent(smalldbg::StopReason::None, 5000)
            != smalldbg::StopReason::None);

    auto thread = s.vmThread();
    REQUIRE(thread);

    const std::string json = s.listFrames(*thread);
    CHECK(json != "[]");
    CHECK(json.find("\"index\"") != std::string::npos);
    CHECK(json.find("\"label\"") != std::string::npos);
    Json frames = Json::parse(json);
    CHECK(frames[0]["stackPointer"].isString());
    CHECK(frames[0]["framePointer"].isString());
    CHECK(frames[0]["module"].isString());

    s.debugger().detach();
}

