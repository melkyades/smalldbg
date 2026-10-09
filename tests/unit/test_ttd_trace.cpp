#include <doctest/doctest.h>

#include "backends/TTDBackend.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace smalldbg;

namespace {

// Writes a file with the start of a trace header whose process had user
// addresses up to `highest`, and returns its path.
std::string writeTraceHeader(const std::string& name, uint64_t highest) {
    std::vector<char> header(0x100, 0);
    std::string magic = "TTDLog";
    std::copy(magic.begin(), magic.end(), header.begin());
    *reinterpret_cast<uint64_t*>(header.data() + 0x68) = 0x10000;
    *reinterpret_cast<uint64_t*>(header.data() + 0x70) = highest;

    auto path = (std::filesystem::temp_directory_path() / name).string();
    std::ofstream(path, std::ios::binary).write(header.data(), header.size());
    return path;
}

} // namespace

TEST_CASE("a trace's header tells the pointer size of the process it recorded") {
    auto narrow = writeTraceHeader("smalldbg_x86.run", 0x7FFEFFFF);
    auto large = writeTraceHeader("smalldbg_x86_large.run", 0xFFFEFFFF);
    auto wide = writeTraceHeader("smalldbg_x64.run", 0x7FFFFFFEFFFF);

    CHECK(tracePointerSize(narrow) == 4);
    CHECK(tracePointerSize(large) == 4);
    CHECK(tracePointerSize(wide) == 8);

    std::remove(narrow.c_str());
    std::remove(large.c_str());
    std::remove(wide.c_str());
}

TEST_CASE("a file that is not a trace has no pointer size") {
    auto path = (std::filesystem::temp_directory_path()
                 / "smalldbg_not_a_trace.run").string();
    std::ofstream(path, std::ios::binary) << "not a trace";

    CHECK(tracePointerSize(path) == 0);
    CHECK(tracePointerSize("missing.run") == 0);

    std::remove(path.c_str());
}

TEST_CASE("a 32-bit debugger refuses a trace of a 64-bit process") {
    if (hostArch()->pointerSize() != 4) return;

    auto wide = writeTraceHeader("smalldbg_x64_refused.run", 0x7FFFFFFEFFFF);
    Debugger dbg(Mode::External, hostArch(), Debuggee::Trace);

    CHECK(dbg.openTrace(wide) == Status::NotSupported);
    CHECK_FALSE(dbg.isAttached());

    std::remove(wide.c_str());
}
