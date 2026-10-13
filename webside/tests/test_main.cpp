#include <doctest/doctest.h>

#include "Main.h"

#include <vector>

using namespace webside;

namespace {

Invocation parse(std::vector<const char*> words,
                 const DialectInfo& dialect = DialectInfo{"test"}) {
    words.insert(words.begin(), "server");
    return parseCommandLine(static_cast<int>(words.size()),
                            const_cast<char**>(words.data()), dialect);
}

} // namespace

TEST_CASE("the command line names a target, its arguments and the port") {
    auto invocation = parse({"vm.exe", "8080", "--", "image", "--flag"});
    REQUIRE(invocation.ok);
    CHECK(invocation.spec.kind == TargetKind::Launch);
    CHECK(invocation.spec.path == "vm.exe");
    CHECK(invocation.spec.args ==
          std::vector<std::string>{"8080", "image", "--flag"});
    CHECK(invocation.port == 7000);
}

TEST_CASE("a bare number before the target is the port") {
    auto invocation = parse({"8080", "vm.exe"});
    REQUIRE(invocation.ok);
    CHECK(invocation.port == 8080);
    CHECK(invocation.spec.path == "vm.exe");
}

TEST_CASE("options set the port, the paths, the pause and verbose logging") {
    auto invocation = parse({"--port", "7100", "--symbols", "C:/pdbs",
                             "--source", "C:/src", "--cwd", "C:/run",
                             "--pause-ms", "500", "-v", "vm.exe"});
    REQUIRE(invocation.ok);
    CHECK(invocation.port == 7100);
    CHECK(invocation.symbolPath == "C:/pdbs");
    CHECK(invocation.spec.sourcePath == "C:/src");
    CHECK(invocation.spec.workingDir == "C:/run");
    CHECK(invocation.pauseMs == 500);
    CHECK(invocation.verbose);
    CHECK(invocation.configPath.empty());
}

TEST_CASE("a pid is an attach, which needs no target file") {
    auto invocation = parse({"--pid", "1234"});
    REQUIRE(invocation.ok);
    CHECK(invocation.spec.kind == TargetKind::Attach);
    CHECK(invocation.spec.pid == 1234);
}

TEST_CASE("a dump or a trace keeps its workspace beside it") {
    auto dump = parse({"crash.dmp"});
    REQUIRE(dump.ok);
    CHECK(dump.spec.kind == TargetKind::Dump);
    CHECK(dump.configPath == "crash.dmp.workspace.json");

    auto trace = parse({"run.run", "--workspace", "mine.json"});
    REQUIRE(trace.ok);
    CHECK(trace.spec.kind == TargetKind::Trace);
    CHECK(trace.configPath == "mine.json");
}

TEST_CASE("a wrong command line is refused") {
    CHECK_FALSE(parse({}).ok);
    CHECK_FALSE(parse({"--prot", "7000", "vm.exe"}).ok);
    CHECK_FALSE(parse({"vm.exe", "--port"}).ok);
}

TEST_CASE("a target the dialect cannot open is refused") {
    DialectInfo launchOnly{"test"};
    launchOnly.opensDump = false;
    CHECK_FALSE(parse({"crash.dmp"}, launchOnly).ok);
    CHECK(parse({"vm.exe"}, launchOnly).ok);
}
