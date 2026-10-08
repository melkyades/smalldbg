#include <doctest/doctest.h>

#include "Json.h"
#include "StubSession.h"
#include "WebsideServer.h"
#include "Workspace.h"
#include "smalldbg/Snapshot.h"

#include <memory>
#include <vector>

using namespace webside;

namespace {

constexpr uint64_t kBase = 0x10000;

// A session whose target is a snapshot of `kBase`, which reads like a stopped
// process.
struct SnapshotSession : StubSession {
    explicit SnapshotSession(std::vector<uint8_t> memory) {
        REQUIRE(snapshot->openSnapshot({
            smalldbg::SnapshotRegion::fromBytes(kBase, std::move(memory))})
            == smalldbg::Status::Ok);
    }
    bool isActive() const override { return true; }
    smalldbg::Debugger& debugger() const override { return *snapshot; }

    const std::unique_ptr<smalldbg::Debugger> snapshot{
        std::make_unique<smalldbg::Debugger>(
            smalldbg::Mode::External, nullptr, smalldbg::Debuggee::Snapshot)};
};

// A server with nothing of its own, whose routes the tests call directly.
struct TestServer : WebsideServer {
    using WebsideServer::WebsideServer;
    using WebsideServer::handleMemory;
    using WebsideServer::handleLoadModuleSymbols;
    using WebsideServer::handleRunTo;

    std::string dialect() const override { return "test"; }
    std::string description() const override { return "test"; }
};

// A workspace with a snapshot of `memory` open, and a server over it.
struct Served {
    explicit Served(std::vector<uint8_t> memory)
        : workspace([memory](const TargetSpec&) {
              return std::make_unique<SnapshotSession>(memory);
          }) {
        TargetSpec target;
        target.path = "snapshot";
        REQUIRE(workspace.open(target));
    }

    Json memory(const std::string& query) {
        HttpRequest request;
        request.method = "GET";
        request.path = "/memory";
        size_t at = 0;
        while (at < query.size()) {
            size_t amp = query.find('&', at);
            std::string field = query.substr(at, amp - at);
            size_t equals = field.find('=');
            request.params[field.substr(0, equals)] = field.substr(equals + 1);
            at = amp == std::string::npos ? query.size() : amp + 1;
        }
        return Json::parse(server.handleMemory(request).body);
    }

    Workspace workspace;
    TestServer server{workspace, 0};
};

std::vector<uint8_t> sample() {
    return {'h', 'i', 0, '!', 0xfe, 0xff, 0xff, 0xff,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88};
}

} // namespace

TEST_CASE("/memory reads bytes as a hex dump beside their ASCII") {
    Served served(sample());
    Json bytes = served.memory("address=0x10000&count=4");
    CHECK(bytes["hex"].asString() == "68 69 00 21");
    CHECK(bytes["ascii"].asString() == "hi.!");
    CHECK(bytes["size"].asInt() == 4);

    Json failed = served.memory("address=0x20000&count=4");
    CHECK(failed["error"].asString() == "Failed to read memory");
}

TEST_CASE("/memory reads a C string up to its terminator") {
    Served served(sample());
    Json text = served.memory("address=0x10000&type=string&count=8");
    CHECK(text["value"].asString() == "hi");
    CHECK(text["size"].asInt() == 2);
}

TEST_CASE("/memory reads fixed-width values, signed or not") {
    Served served(sample());
    Json signedWords = served.memory("address=0x10004&type=int32&count=1");
    CHECK(signedWords["values"][0].asInt() == -2);

    Json unsignedWords = served.memory("address=0x10004&type=uint16&count=2");
    CHECK(unsignedWords["values"][0].asInt() == 0xfffe);
    CHECK(unsignedWords["values"][1].asInt() == 0xffff);

    Json bytes = served.memory("address=0x10008&type=uint8&count=2");
    CHECK(bytes["values"][1].asInt() == 2);
}

TEST_CASE("/memory reports a string or values it cannot read") {
    Served served(sample());
    CHECK(served.memory("address=0x1000c&type=uint32&count=2")["error"]
              .asString() == "Failed to read memory");
    CHECK(served.memory("address=0x20000&type=string&count=8")["error"]
              .asString() == "Failed to read memory");
}

TEST_CASE("/memory gives 64-bit values as hex when asked, to keep them exact") {
    Served served(sample());
    Json hex = served.memory("address=0x10008&type=uint64&count=1&format=hex");
    CHECK(hex["values"][0].asString() ==
          Json::hex(uint64_t(0x8807060504030201)).asString());
}

TEST_CASE("loading a module's symbols reports them, and the workspace keeps it") {
    Workspace workspace([](const TargetSpec&) {
        return std::make_unique<LiveSession>();
    });
    TargetSpec target;
    target.path = WEBSIDE_TEST_TARGET;
    REQUIRE(workspace.open(target));
    auto& live = *workspace.session();
    REQUIRE(live.debugger().waitForEvent(smalldbg::StopReason::None, 5000)
            != smalldbg::StopReason::None);
    TestServer server{workspace, 0};

    HttpRequest request;
    request.method = "POST";
    request.path = "/native-modules/test_target/symbols";
    Json loaded = Json::parse(server.handleLoadModuleSymbols(request).body);
    CHECK(loaded["name"].asString() == "test_target");
    CHECK(loaded["loaded"].asBool());
    CHECK_FALSE(loaded["symbolFile"].asString().empty());
    CHECK(workspace.symbolModules() == std::vector<std::string>{"test_target"});

    request.path = "/native-modules/no_such_module/symbols";
    HttpResponse missing = server.handleLoadModuleSymbols(request);
    CHECK(missing.statusCode == 404);

    live.debugger().detach();
}

TEST_CASE("a debugger runs its thread to the address it is given") {
    Workspace workspace([](const TargetSpec&) {
        return std::make_unique<LiveSession>();
    });
    TargetSpec target;
    target.path = WEBSIDE_TEST_TARGET;
    REQUIRE(workspace.open(target));
    auto& debugger = workspace.session()->debugger();
    REQUIRE(debugger.waitForEvent(smalldbg::StopReason::None, 5000)
            != smalldbg::StopReason::None);
    auto breakHere = debugger.getSymbolProvider()->getSymbolByName(
        "test_target!break_here");
    REQUIRE(breakHere.has_value());
    TestServer server{workspace, 0};

    HttpRequest request;
    request.method = "POST";
    request.path = "/debuggers/1/runto";
    request.body = Json::object()
        .set("address", Json::hex(breakHere->address)).dump();
    Json answer = Json::parse(server.handleRunTo(request, false).body);
    CHECK(answer["success"].asBool());
    smalldbg::Registers regs;
    REQUIRE(debugger.getRegisters(regs) == smalldbg::Status::Ok);
    CHECK(regs.ip() == breakHere->address);

    request.body = "{}";
    CHECK(server.handleRunTo(request, false).statusCode == 400);

    debugger.detach();
}
