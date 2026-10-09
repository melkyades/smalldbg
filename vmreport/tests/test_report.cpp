#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "Report.h"

#include <Setup.h>
#include <smalldbg/Arch.h>
#include <smalldbg/Debugger.h>
#include <smalldbg/Snapshot.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace {

// A path in the temporary directory, removed with the setup beside it when
// the test ends.
struct TempTarget {
    explicit TempTarget(const std::string& name)
        : path((std::filesystem::temp_directory_path() / name).string()) {}
    ~TempTarget() {
        std::filesystem::remove(path);
        std::filesystem::remove(path + ".workspace.json");
        std::filesystem::remove(path + ".report.txt");
    }
    std::string path;
};

bool parse(std::vector<const char*> words, vmreport::Options& options) {
    words.insert(words.begin(), "vmreport");
    return vmreport::parseCommandLine(static_cast<int>(words.size()),
                                      const_cast<char**>(words.data()),
                                      options);
}

std::string readFile(const std::string& path) {
    std::ifstream file(path);
    std::stringstream text;
    text << file.rdbuf();
    return text.str();
}

} // namespace

TEST_CASE("the command line names the target and, by default, the report") {
    vmreport::Options options;
    CHECK_FALSE(parse({}, options));

    REQUIRE(parse({"crash.dmp", "--symbols", "C:/pdbs", "--source", "src"},
                  options));
    CHECK(options.target == "crash.dmp");
    CHECK(options.output == "crash.dmp.report.txt");
    CHECK(options.symbols == "C:/pdbs");
    CHECK(options.sources == "src");

    REQUIRE(parse({"crash.dmp", "-o", "mine.txt"}, options));
    CHECK(options.output == "mine.txt");
}

TEST_CASE("without --symbols, the symbol paths come from the setup beside it") {
    TempTarget target("vmreport-setup-target.dmp");
    vmdbg::Setup setup;
    setup.setConfigPath(target.path + ".workspace.json");
    setup.setSymbolSearchPath("C:/a;C:/b");

    vmreport::Options options;
    REQUIRE(parse({target.path.c_str()}, options));
    CHECK(options.symbols == "C:/a;C:/b");
}

TEST_CASE("a report says why the target stopped, then the VM, then threads") {
    TempTarget target("vmreport-snapshot.dmp");
    vmreport::Options options;
    options.target = target.path;
    options.output = target.path + ".report.txt";

    smalldbg::Debugger debugger(smalldbg::Mode::External,
                                smalldbg::X64::instance(),
                                smalldbg::Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({smalldbg::SnapshotRegion::fromBytes(
                0x1000, std::vector<uint8_t>(16))})
            == smalldbg::Status::Ok);

    int status = vmreport::writeReportFile(debugger, options,
        [](std::ostream& out) { vmreport::heading(out, "The VM"); });
    REQUIRE(status == 0);

    std::string report = readFile(options.output);
    size_t why = report.find("Why it stopped");
    size_t vm = report.find("The VM");
    size_t threads = report.find("Native threads (0)");
    REQUIRE(why != std::string::npos);
    REQUIRE(vm != std::string::npos);
    REQUIRE(threads != std::string::npos);
    CHECK(why < vm);
    CHECK(vm < threads);
    CHECK(report.find("no stop") != std::string::npos);
}

TEST_CASE("an address is written in hex, padded to the width asked") {
    CHECK(vmreport::hex(0x1f, 8) == "0x0000001f");
    CHECK(vmreport::hex(0x1f) == "0x000000000000001f");
}
