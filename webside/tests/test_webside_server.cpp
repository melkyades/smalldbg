#include <doctest/doctest.h>

#include "Json.h"
#include "StubSession.h"
#include "WebsideServer.h"
#include "Workspace.h"
#include "smalldbg/Process.h"
#include "smalldbg/Snapshot.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Thread.h"

#include <httplib/httplib.h>

#include <chrono>
#include <memory>
#include <thread>
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
    using WebsideServer::handleRegions;
    using WebsideServer::handleMemoryTypesGet;
    using WebsideServer::handleDisassemble;
    using WebsideServer::handleMemoryTypesSet;
    using WebsideServer::handleMemoryTypesClear;
    using WebsideServer::handleClassify;
    using WebsideServer::handleLoadModuleSymbols;
    using WebsideServer::handleRunTo;
    using WebsideServer::threadListJson;
    using WebsideServer::debuggerListJson;
    using WebsideServer::frameWarning;
    using WebsideServer::warn;
    using WebsideServer::runControlResult;
    using WebsideServer::stackDescriptors;
    using WebsideServer::handleDebuggerRoute;
    using WebsideServer::nativeSymbolsData;
    using WebsideServer::nativeInspectData;

    void stop() { server.stop(); }

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

// A live session with `greenThreads` green threads, which run on the OS
// thread set in `runner`, or on none while it is 0.
struct GreenSession : LiveSession {
    int greenThreadCount() const override { return greenThreads; }
    std::string getGreenThreadName(int) const override { return "green"; }
    uint64_t nativeThreadOf(int) const override { return runner; }
    smalldbg::StackTrace* greenStack(int) const override { return parked.get(); }

    int greenThreads{0};
    uint64_t runner{0};
    std::unique_ptr<smalldbg::StackTrace> parked;
};

// A workspace with the test target launched and stopped, and a server over it.
struct Launched {
    explicit Launched(std::vector<std::string> args = {})
        : workspace([](const TargetSpec&) {
              return std::make_unique<GreenSession>();
          }) {
        TargetSpec target;
        target.path = WEBSIDE_TEST_TARGET;
        target.args = std::move(args);
        REQUIRE(workspace.open(target));
        REQUIRE(debugger().waitForEvent(smalldbg::StopReason::None, 5000)
                != smalldbg::StopReason::None);
    }
    ~Launched() { debugger().detach(); }

    smalldbg::Debugger& debugger() { return workspace.session()->debugger(); }

    smalldbg::Symbol symbol(const std::string& name) {
        auto found = debugger().getSymbolProvider()->getSymbolByName(name);
        REQUIRE(found.has_value());
        return *found;
    }

    void stopAtBreakHere() {
        REQUIRE(debugger().runTo(symbol("test_target!break_here").address, 30000)
                == smalldbg::Status::Ok);
    }

    Workspace workspace;
    TestServer server{workspace, 0};
};

std::vector<uint8_t> sample() {
    return {'h', 'i', 0, '!', 0xfe, 0xff, 0xff, 0xff,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88};
}

} // namespace

// Eden runs over the first 16 bytes of the snapshot, half of them in use.
void addEden(Served& served) {
    vmdbg::Region eden;
    eden.name = "eden";
    eden.start = kBase;
    eden.end = kBase + 0x10;
    eden.kind = vmdbg::Region::Kind::Objects;
    eden.top = kBase + 8;
    eden.note = "young objects";
    static_cast<StubSession&>(*served.workspace.session())
        .ownedInspector->add(eden);
}

Json classify(Served& served, uint64_t address) {
    HttpRequest request;
    request.method = "GET";
    request.path = "/classify";
    request.params["address"] = Json::hex(address).asString();
    return Json::parse(served.server.handleClassify(request).body);
}

TEST_CASE("/regions lists the VM's regions with their kind and use") {
    Served served(sample());
    addEden(served);
    HttpRequest request;
    request.method = "GET";
    request.path = "/regions";
    Json regions = Json::parse(served.server.handleRegions(request).body)["regions"];
    REQUIRE(regions.size() == 1);
    CHECK(regions[0]["name"].asString() == "eden");
    CHECK(regions[0]["kind"].asString() == "objects");
    CHECK(regions[0]["size"].asInt() == 16);
    CHECK(regions[0]["top"].asString() == Json::hex(kBase + 8).asString());
    CHECK(regions[0]["note"].asString() == "young objects");
}

TEST_CASE("/classify says which region holds an address and if it is in use") {
    Served served(sample());
    addEden(served);
    Json used = classify(served, kBase + 2);
    CHECK(used["region"].asString() == "eden");
    CHECK(used["kind"].asString() == "objects");
    CHECK(used["regionOffset"].asInt() == 2);
    CHECK(used["free"].isNull());
    CHECK(classify(served, kBase + 12)["free"].asBool());
    CHECK(classify(served, kBase + 0x20)["region"].isNull());
}

HttpRequest request(const std::string& method, const std::string& path,
                    const std::string& body = {}) {
    HttpRequest made;
    made.method = method;
    made.path = path;
    made.body = body;
    return made;
}

Json memoryTypes(Served& served, uint64_t address, int count) {
    HttpRequest get = request("GET", "/memory-types");
    get.params["address"] = Json::hex(address).asString();
    get.params["count"] = std::to_string(count);
    return Json::parse(served.server.handleMemoryTypesGet(get).body)["ranges"];
}

Json setMemoryType(Served& served, uint64_t start, const std::string& type) {
    std::string body = Json::object().set("start", Json::hex(start))
                                     .set("type", type).dump();
    return Json::parse(
        served.server.handleMemoryTypesSet(request("POST", "/memory-types", body)).body);
}

TEST_CASE("memory types default to what the regions hold") {
    Served served(sample());
    addEden(served);
    Json ranges = memoryTypes(served, kBase, 16);
    REQUIRE(ranges.size() == 1);
    CHECK(ranges[0]["type"].asString() == "data8");
    CHECK(ranges[0]["heap"].asBool());
    CHECK_FALSE(ranges[0]["user"].asBool());
}

TEST_CASE("a memory type set without an end covers what is there") {
    Served text(sample());
    Json string = setMemoryType(text, kBase, "ascii");
    CHECK(string["size"].asInt() == 3);
    CHECK(string["user"].asBool());
    Json ranges = memoryTypes(text, kBase, 3);
    REQUIRE(ranges.size() == 1);
    CHECK(ranges[0]["type"].asString() == "ascii");

    HttpRequest clear = request("DELETE", "/memory-types");
    clear.params["address"] = Json::hex(kBase).asString();
    clear.params["count"] = "3";
    text.server.handleMemoryTypesClear(clear);
    CHECK_FALSE(memoryTypes(text, kBase, 3)[0]["user"].asBool());

    Served code({0x90, 0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC});
    CHECK(setMemoryType(code, kBase, "code")["size"].asInt() == 3);
}

TEST_CASE("a listing shows code, strings and data as the memory types say") {
    Served served({0x90, 0xC3, 'h', 'i', 0, 0, 0, 0,
                   0x2A, 0, 0, 0, 0, 0, 0, 0});
    REQUIRE(setMemoryType(served, kBase, "code")["size"].asInt() == 2);
    REQUIRE(setMemoryType(served, kBase + 2, "ascii")["size"].asInt() == 3);
    served.workspace.setLabel(kBase, "start");

    HttpRequest get = request("GET", "/disassemble");
    get.params["address"] = Json::hex(kBase).asString();
    get.params["count"] = "16";
    Json rows = Json::parse(served.server.handleDisassemble(get).body)["instructions"];
    REQUIRE(rows.size() >= 5);
    CHECK(rows[0]["type"].asString() == "label");
    CHECK(rows[0]["text"].asString() == "start");
    CHECK(rows[0]["user"].asBool());
    CHECK(rows[1]["text"].asString().rfind("nop", 0) == 0);
    CHECK(rows[2]["text"].asString().rfind("ret", 0) == 0);
    CHECK(rows[3]["type"].asString() == "string");
    CHECK(rows[3]["value"].asString() == "hi");
    CHECK(rows[4]["type"].asString() == "data");
    CHECK(rows[4]["text"].asString() == "db 0x00");
    CHECK(rows[rows.size() - 1]["text"].asString() == "dq 0x000000000000002a");
}

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
    Launched launched;
    HttpRequest request;
    request.method = "POST";
    request.path = "/native-modules/test_target/symbols";
    Json loaded = Json::parse(
        launched.server.handleLoadModuleSymbols(request).body);
    CHECK(loaded["name"].asString() == "test_target");
    CHECK(loaded["loaded"].asBool());
    CHECK_FALSE(loaded["symbolFile"].asString().empty());
    CHECK(launched.workspace.symbolModules()
          == std::vector<std::string>{"test_target"});

    request.path = "/native-modules/no_such_module/symbols";
    CHECK(launched.server.handleLoadModuleSymbols(request).statusCode == 404);
}

TEST_CASE("a debugger runs its thread to the address it is given") {
    Launched launched;
    smalldbg::Address breakHere = launched.symbol("test_target!break_here").address;

    HttpRequest request;
    request.method = "POST";
    request.path = "/debuggers/1/runto";
    request.body = Json::object().set("address", Json::hex(breakHere)).dump();
    Json answer = Json::parse(launched.server.handleRunTo(request, false).body);
    CHECK(answer["success"].asBool());
    smalldbg::Registers regs;
    REQUIRE(launched.debugger().getRegisters(regs) == smalldbg::Status::Ok);
    CHECK(regs.ip() == breakHere);

    request.body = "{}";
    CHECK(launched.server.handleRunTo(request, false).statusCode == 400);
}

TEST_CASE("/threads names each thread and marks the VM's as main") {
    Launched launched;
    launched.stopAtBreakHere();

    Json threads = Json::parse(launched.server.threadListJson());
    REQUIRE(threads.size() >= 1);
    int mains = 0;
    for (const Json& thread : threads.elements()) {
        CHECK(thread["type"].asString() == "native");
        if (!thread["isMain"].asBool()) continue;
        mains++;
        CHECK(thread["name"].asString().rfind("test_target!", 0) == 0);
    }
    CHECK(mains == 1);

    Json debuggers = Json::parse(launched.server.debuggerListJson());
    CHECK(debuggers.size() >= threads.size());
}

TEST_CASE("frames that cannot be trusted come with a warning header") {
    Served served(sample());
    smalldbg::Thread thread(nullptr, 1);
    std::string warning = served.server.frameWarning(thread);
    CHECK(warning == "registers for this thread could not be read");

    HttpResponse response;
    TestServer::warn(response, warning);
    CHECK(response.headers["X-Webside-Warning"] == warning);
    HttpResponse quiet;
    TestServer::warn(quiet, "");
    CHECK(quiet.headers.empty());
}

// An inlined frame, the frame it is inlined into, and its caller, which
// returns into "outer" 0x10 bytes in. The slot past the caller's return
// address belongs to no frame.
TEST_CASE("each stack slot is placed in the innermost frame that owns it") {
    const uint64_t slot = 8;  // a snapshot reads as a 64-bit target
    std::vector<uint8_t> memory(0x100);
    memory[3 * slot] = 0x10;
    memory[3 * slot + 1] = 0x50;
    Served served(memory);
    WebsideSession& session = *served.workspace.session();
    REQUIRE(session.pointerSize() == slot);

    std::vector<std::unique_ptr<smalldbg::StackFrame>> frames;
    auto frame = [&](uint64_t sp, uint64_t fp, const char* name, bool inlined) {
        auto made = std::make_unique<smalldbg::StackFrame>();
        made->setSp(sp);
        made->setFp(fp);
        made->setIp(0x5020);
        made->functionName = name;
        made->functionStart = 0x5000;
        made->inlined = inlined;
        frames.push_back(std::move(made));
    };
    frame(kBase, kBase + 2 * slot, "inlined", true);
    frame(kBase, kBase + 2 * slot, "inner", false);
    frame(kBase + 4 * slot, kBase + 5 * slot, "outer", false);
    smalldbg::StackTrace trace(nullptr, std::move(frames));

    Json slots = Json::parse(session.stackDescriptors(trace, 1, kBase, 8));
    REQUIRE(slots.size() == 7);
    CHECK(slots[0]["role"].asString() == "sp");
    CHECK(slots[0]["frameIndex"].asInt() == 2);
    CHECK(slots[0]["frameRel"].asInt() == 0);
    CHECK(slots[2]["role"].asString() == "fp");
    CHECK(slots[3]["role"].asString() == "retAddr");
    CHECK(slots[3]["printString"].asString() == "outer+16");
    CHECK(slots[4]["frameIndex"].asInt() == 3);
    CHECK(slots[4]["frameRel"].asInt() == 1);
}

TEST_CASE("a symbol search finds a name from part of it") {
    Launched launched;
    launched.stopAtBreakHere();
    Json found = Json::parse(launched.server.nativeSymbolsData("break_her"));
    bool named = false;
    for (const Json& symbol : found.elements())
        named = named || symbol["name"].asString() == "break_here";
    CHECK(named);
}

TEST_CASE("a symbol's address has the target's width") {
    Launched launched;
    launched.stopAtBreakHere();
    Json found = Json::parse(launched.server.nativeSymbolsData("break_her"));
    REQUIRE(found.size() > 0);
    const size_t digits = 2 * launched.workspace.session()->pointerSize();
    CHECK(found[0]["address"].asString().size() == 2 + digits);
}

TEST_CASE("native inspection gives a field its own size") {
    Launched launched;
    launched.stopAtBreakHere();
    const size_t pointer = launched.debugger().arch()->pointerSize();

    Json label = Json::parse(
        launched.server.nativeInspectData("test_target!g_test_record.label"));
    CHECK(label["size"].asInt() == static_cast<int64_t>(pointer));
    CHECK(label["type"].asString().find("char") != std::string::npos);

    Json id = Json::parse(
        launched.server.nativeInspectData("test_target!g_test_record.id"));
    CHECK(id["size"].asInt() == 4);
    CHECK(id["value"].asString() == Json::hex(uint64_t(7)).asString());
}

TEST_CASE("a run-control answer forgets a refusal met while moving") {
    Served served(sample());
    smalldbg::markEngineBusy();
    Json answer = Json::parse(served.server.runControlResult(true));
    CHECK(answer["success"].asBool());
    CHECK_FALSE(smalldbg::engineWasBusy());
}

TEST_CASE("a thread's stack is described from that thread's frames") {
    Launched launched({"deep"});
    launched.stopAtBreakHere();
    auto current = launched.debugger().getCurrentThread();
    std::shared_ptr<smalldbg::Thread> worker;
    for (const auto& thread : launched.debugger().getProcess()->threads()) {
        if (thread->getThreadId() == current->getThreadId()) continue;
        for (const auto& frame : thread->getStackTrace(64)->getFrames())
            if (frame->functionName == "deep_worker") worker = thread;
    }
    REQUIRE(worker.get() != nullptr);

    smalldbg::Registers regs;
    REQUIRE(launched.debugger().getRegisters(worker.get(), regs)
            == smalldbg::Status::Ok);
    Json slots = Json::parse(
        launched.server.stackDescriptors(*worker, 1, regs.sp(), 16));
    bool stackPointer = false;
    for (const Json& slot : slots.elements())
        stackPointer = stackPointer || slot["role"].asString() == "sp";
    CHECK(stackPointer);
}

TEST_CASE("a running green thread's frames come from the OS thread running it") {
    Launched launched;
    launched.stopAtBreakHere();
    auto& green = static_cast<GreenSession&>(*launched.workspace.session());
    green.greenThreads = 1;
    int greenId = static_cast<int>(
        launched.debugger().getProcess()->threads().size()) + 1;
    HttpRequest request;
    request.method = "GET";
    request.path = "/debuggers/" + std::to_string(greenId) + "/frames";

    CHECK(launched.server.handleDebuggerRoute(request).body == "[]");

    green.runner = launched.debugger().getCurrentThread()->getThreadId();
    Json frames = Json::parse(launched.server.handleDebuggerRoute(request).body);
    REQUIRE(frames.size() > 0);
    CHECK(frames[0]["label"].asString().find("break_here") != std::string::npos);
}

TEST_CASE("a parked green thread's frames are answered as a native thread's") {
    Launched launched;
    auto& green = static_cast<GreenSession&>(*launched.workspace.session());
    green.greenThreads = 1;
    std::vector<std::unique_ptr<smalldbg::StackFrame>> frames;
    for (const char* name : {"inner", "outer"}) {
        auto frame = std::make_unique<smalldbg::StackFrame>();
        frame->functionName = name;
        frame->setIp(0x1000);
        frame->setFp(0x2000);
        frames.push_back(std::move(frame));
    }
    green.parked = std::make_unique<smalldbg::StackTrace>(nullptr, std::move(frames));
    std::string path = "/debuggers/" + std::to_string(
        launched.debugger().getProcess()->threads().size() + 1) + "/frames";
    HttpRequest request;
    request.method = "GET";

    request.path = path;
    Json listed = Json::parse(launched.server.handleDebuggerRoute(request).body);
    REQUIRE(listed.size() == 2);
    CHECK(listed[1]["label"].asString() == "outer");

    request.path = path + "/2/registers";
    Json registers = Json::parse(launched.server.handleDebuggerRoute(request).body);
    CHECK(registers[0]["printString"].asString() == "outer");
    CHECK(registers[3]["value"].isNull());

    request.path = path + "/3";
    CHECK(launched.server.handleDebuggerRoute(request).statusCode == 404);
}

TEST_CASE("a green thread's stack is placed relative to the frame selected") {
    Launched launched;
    auto& green = static_cast<GreenSession&>(*launched.workspace.session());
    green.greenThreads = 1;
    int greenId = static_cast<int>(
        launched.debugger().getProcess()->threads().size()) + 1;
    HttpRequest request;
    request.method = "GET";
    request.path = "/debuggers/" + std::to_string(greenId) + "/stack";
    request.params["frame"] = "3";
    launched.server.handleDebuggerRoute(request);
    CHECK(green.lastSelectedFrame == 3);
}

TEST_CASE("with nothing open, only the routes that need no target answer") {
    constexpr int port = 47232;
    Workspace workspace([](const TargetSpec&) {
        return std::make_unique<StubSession>();
    });
    TestServer server{workspace, port};
    std::thread serving([&] { server.run(); });

    httplib::Client client("127.0.0.1", port);
    httplib::Result logo;
    for (int attempt = 0; attempt < 50 && !logo; attempt++) {
        logo = client.Get("/logo");
        if (!logo) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    REQUIRE(logo);
    CHECK(logo->status == 200);
    CHECK(client.Get("/dialect")->body == "\"test\"");
    CHECK(client.Get("/themes")->status == 200);
    CHECK(client.Get("/classes")->status == 503);
    CHECK(client.Get("/threads")->status == 503);

    server.stop();
    serving.join();
}

TEST_CASE("the workspace, its breakpoints and labels answer with nothing open") {
    constexpr int port = 47233;
    Workspace workspace([](const TargetSpec&) {
        return std::make_unique<StubSession>();
    });
    workspace.setBreakpoint(0x401000, "start");
    TestServer server{workspace, port};
    std::thread serving([&] { server.run(); });

    httplib::Client client("127.0.0.1", port);
    httplib::Result breakpoints;
    for (int attempt = 0; attempt < 50 && !breakpoints; attempt++) {
        breakpoints = client.Get("/breakpoints");
        if (!breakpoints) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    REQUIRE(breakpoints);
    Json listed = Json::parse(breakpoints->body);
    REQUIRE(listed.size() == 1);
    CHECK(listed[0]["address"].asString() == Json::hex(uint64_t(0x401000)).asString());
    CHECK(listed[0]["name"].asString() == "start");

    auto setup = client.Get("/workspace");
    REQUIRE(setup);
    CHECK(Json::parse(setup->body)["breakpoints"].size() == 1);

    auto set = client.Post("/breakpoints",
                           "{\"address\":\"0x402000\",\"name\":\"two\"}",
                           "application/json");
    REQUIRE(set);
    CHECK(Json::parse(set->body)["success"].asBool());
    CHECK(Json::parse(client.Get("/breakpoints")->body).size() == 2);
    auto cleared = client.Delete("/breakpoints", "{\"address\":4198400}",
                                 "application/json");
    REQUIRE(cleared);
    CHECK(Json::parse(cleared->body)["success"].asBool());
    CHECK(Json::parse(client.Get("/breakpoints")->body).size() == 1);

    REQUIRE(client.Post("/labels", "{\"address\":\"0x403000\",\"name\":\"buffer\"}",
                        "application/json"));
    Json labels = Json::parse(client.Get("/labels")->body);
    REQUIRE(labels.size() == 1);
    CHECK(labels[0]["name"].asString() == "buffer");
    CHECK(labels[0]["address"].asString() == Json::hex(uint64_t(0x403000)).asString());
    REQUIRE(client.Delete("/labels?address=0x403000"));
    CHECK(Json::parse(client.Get("/labels")->body).size() == 0);

    server.stop();
    serving.join();
}

TEST_CASE("a target that is no trace has no position and refuses to move") {
    constexpr int port = 47234;
    Workspace workspace([](const TargetSpec&) {
        return std::make_unique<SnapshotSession>(sample());
    });
    TargetSpec target;
    target.path = "snapshot";
    REQUIRE(workspace.open(target));
    TestServer server{workspace, port};
    std::thread serving([&] { server.run(); });

    httplib::Client client("127.0.0.1", port);
    httplib::Result position;
    for (int attempt = 0; attempt < 50 && !position; attempt++) {
        position = client.Get("/trace/position");
        if (!position) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    REQUIRE(position);
    CHECK(position->body == "{}");
    for (const char* asked : {"{\"position\":\"1A:2\"}", "{\"position\":\"50\"}",
                              "{\"position\":\"1A:zz\"}", "{\"position\":\"150%\"}"}) {
        auto moved = client.Post("/trace/position", asked, "application/json");
        REQUIRE(moved);
        CHECK(moved->status == 400);
    }

    server.stop();
    serving.join();
}
