#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace smalldbg;

namespace {

std::vector<uint8_t> bytesOf(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::string read(Debugger& dbg, Address address, size_t size) {
    std::string out(size, '\0');
    if (dbg.readMemory(address, out.data(), size) != Status::Ok) return "<failed>";
    return out;
}

// A file of known contents, removed when the test is done with it. The name is
// random, so two runs of the suite at once, from two builds, do not share it.
struct TempFile {
    std::filesystem::path path;

    explicit TempFile(const std::string& contents)
        : path(std::filesystem::temp_directory_path()
               / ("smalldbg_snapshot_" + std::to_string(std::random_device{}()) + ".bin")) {
        std::ofstream(path, std::ios::binary) << contents;
    }
    ~TempFile() { std::filesystem::remove(path); }
};

} // namespace

TEST_CASE("a Debugger built for a process does not open a snapshot") {
    Debugger dbg(Mode::External);
    CHECK(dbg.openSnapshot({SnapshotRegion::fromBytes(0x1000, bytesOf("abc"))})
          == Status::NotSupported);
}

TEST_CASE("a snapshot reads its regions back at their addresses") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({
        SnapshotRegion::fromBytes(0x2000, bytesOf("world")),
        SnapshotRegion::fromBytes(0x1000, bytesOf("hello")),
        SnapshotRegion::fromBytes(0x1005, bytesOf(", ")),
    }) == Status::Ok);

    CHECK(dbg.isAttached());
    CHECK(read(dbg, 0x2000, 5) == "world");
    CHECK(read(dbg, 0x1001, 3) == "ell");
    CHECK(read(dbg, 0x1003, 4) == "lo, ");
}

TEST_CASE("a read a snapshot does not hold fails and leaves the buffer alone") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({SnapshotRegion::fromBytes(0x1000, bytesOf("abcd"))})
            == Status::Ok);

    char out[8] = "unread";
    CHECK(dbg.readMemory(0x1002, out, 4) == Status::Error);
    CHECK(std::string(out) == "unread");
    CHECK(dbg.readMemory(0x0ffc, out, 2) == Status::Error);
}

TEST_CASE("overlapping regions are refused") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    CHECK(dbg.openSnapshot({
        SnapshotRegion::fromBytes(0x1000, bytesOf("abcd")),
        SnapshotRegion::fromBytes(0x1002, bytesOf("xy")),
    }) == Status::Error);
    CHECK_FALSE(dbg.isAttached());
}

TEST_CASE("a region read from a file starts at its offset") {
    TempFile file("headerPAYLOAD");
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({SnapshotRegion::fromFile(0x4000, file.path.string(), 6, 7)})
            == Status::Ok);
    CHECK(read(dbg, 0x4000, 7) == "PAYLOAD");
}

TEST_CASE("a file that is missing or too short does not open") {
    Debugger missing(Mode::External, nullptr, Debuggee::Snapshot);
    CHECK(missing.openSnapshot({SnapshotRegion::fromFile(0, "no/such/file.bin", 0, 4)})
          == Status::NotFound);

    TempFile file("short");
    Debugger tooShort(Mode::External, nullptr, Debuggee::Snapshot);
    CHECK(tooShort.openSnapshot({SnapshotRegion::fromFile(0, file.path.string(), 2, 8)})
          == Status::Error);
}

TEST_CASE("a snapshot is stopped, has no threads and refuses to run") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({SnapshotRegion::fromBytes(0x1000, bytesOf("code"))})
            == Status::Ok);

    CHECK(dbg.isStopped());
    REQUIRE(dbg.getProcess() != nullptr);
    CHECK(dbg.getProcess()->threads().empty());
    CHECK(dbg.resume() == Status::NotSupported);
    CHECK(dbg.setBreakpoint(0x1000) == Status::NotSupported);
    uint8_t byte = 0;
    CHECK(dbg.writeMemory(0x1000, &byte, 1) == Status::NotSupported);

    CHECK(dbg.detach() == Status::Ok);
    CHECK_FALSE(dbg.isAttached());
    CHECK(read(dbg, 0x1000, 4) == "<failed>");
}
