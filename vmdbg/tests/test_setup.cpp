#include <doctest/doctest.h>

#include "Setup.h"

#include <filesystem>
#include <fstream>

using vmdbg::Setup;
using vmdbg::TargetKind;
using vmdbg::TargetSpec;

namespace {

// A file in the temporary directory, removed when the test ends.
struct TempFile {
    explicit TempFile(const std::string& name)
        : path((std::filesystem::temp_directory_path() / name).string()) {
        std::filesystem::remove(path);
    }
    ~TempFile() { std::filesystem::remove(path); }
    std::string path;
};

} // namespace

TEST_CASE("a setup written to a file reads back the same") {
    TempFile file("vmdbg-setup-roundtrip.json");
    Setup written;
    TargetSpec target;
    target.kind = TargetKind::Dump;
    target.path = "crash.dmp";
    target.args = {"-x"};
    written.setTarget(target);
    written.setSymbolSearchPath("C:/pdbs;;D:/more");
    written.rememberSymbolModule("vm");
    written.setBreakpoint(0x401000, "start");
    written.setLabel(0x7ff0, "table");
    written.setConfigPath(file.path);
    REQUIRE(written.save());

    Setup read;
    REQUIRE(read.load(file.path));
    CHECK(read.target().kind == TargetKind::Dump);
    CHECK(read.target().path == "crash.dmp");
    CHECK(read.target().args == std::vector<std::string>{"-x"});
    CHECK(read.symbolSearchPath() == "C:/pdbs;D:/more");
    CHECK(read.symbolModules() == std::vector<std::string>{"vm"});
    CHECK(read.breakpoints().at(0x401000) == "start");
    CHECK(read.labelAt(0x7ff0) == "table");
}

TEST_CASE("a loaded setup writes every change back to its file") {
    TempFile file("vmdbg-setup-writeback.json");
    Setup first;
    first.setConfigPath(file.path);
    first.setLabel(0x10, "ten");

    Setup second;
    REQUIRE(second.load(file.path));
    second.clearLabel(0x10);
    second.setBreakpoint(0x20, "twenty");

    Setup third;
    REQUIRE(third.load(file.path));
    CHECK(third.labels().empty());
    CHECK(third.breakpoints().size() == 1);
    CHECK_FALSE(third.clearBreakpoint(0x30));
}

TEST_CASE("a missing or unreadable file leaves the setup as it was") {
    TempFile missing("vmdbg-setup-missing.json");
    Setup setup;
    setup.setLabel(0x10, "kept");
    CHECK_FALSE(setup.load(missing.path));
    CHECK(setup.labelAt(0x10) == "kept");

    TempFile broken("vmdbg-setup-broken.json");
    std::ofstream(broken.path) << "{ not json";
    CHECK_FALSE(setup.load(broken.path));
    CHECK(setup.labelAt(0x10) == "kept");
}
