#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Snapshot.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace smalldbg;

namespace {

constexpr uint64_t kBase = 0x400000;

void put32(std::vector<uint8_t>& image, size_t at, uint32_t value) {
    *reinterpret_cast<uint32_t*>(image.data() + at) = value;
}

void put16(std::vector<uint8_t>& image, size_t at, uint16_t value) {
    *reinterpret_cast<uint16_t*>(image.data() + at) = value;
}

// An image with the headers of a PE file and two sections: code at 0x1000
// and data at 0x2000.
std::vector<uint8_t> peImage() {
    std::vector<uint8_t> image(0x3000, 0);
    put16(image, 0, 0x5A4D);           // "MZ"
    put32(image, 0x3C, 0x80);          // where the PE header is
    put32(image, 0x80, 0x00004550);    // "PE\0\0"
    put16(image, 0x84 + 2, 2);         // two sections
    put16(image, 0x84 + 16, 0xE0);     // size of the optional header

    const size_t table = 0x84 + 20 + 0xE0;
    auto section = [&](size_t index, const char* name, uint32_t address,
                       uint32_t size, uint32_t characteristics) {
        const size_t at = table + index * 40;
        std::copy(name, name + std::strlen(name), image.begin() + at);
        put32(image, at + 8, size);
        put32(image, at + 12, address);
        put32(image, at + 36, characteristics);
    };
    section(0, ".text", 0x1000, 0x800, 0x60000020);   // code, executable
    section(1, ".data", 0x2000, 0x2000, 0xC0000040);  // data, runs past the end
    return image;
}

} // namespace

TEST_CASE("a module's sections come from its image headers") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({SnapshotRegion::fromBytes(kBase, peImage())})
            == Status::Ok);
    ModuleInfo module;
    module.loadAddress = kBase;
    module.endAddress = kBase + 0x3000;

    auto sections = dbg.moduleSections(module);
#ifdef _WIN32
    REQUIRE(sections.size() == 2);
    CHECK(sections[0].name == ".text");
    CHECK(sections[0].start == kBase + 0x1000);
    CHECK(sections[0].end == kBase + 0x1800);
    CHECK(sections[0].executable);
    CHECK(sections[1].name == ".data");
    CHECK(sections[1].end == kBase + 0x3000);
    CHECK_FALSE(sections[1].executable);
#else
    CHECK(sections.empty());
#endif
}

TEST_CASE("a module without readable headers has no sections") {
    Debugger dbg(Mode::External, nullptr, Debuggee::Snapshot);
    REQUIRE(dbg.openSnapshot({SnapshotRegion::fromBytes(
                kBase, std::vector<uint8_t>(0x100, 0))}) == Status::Ok);
    ModuleInfo module;
    module.loadAddress = kBase;
    module.endAddress = kBase + 0x100;
    CHECK(dbg.moduleSections(module).empty());

    module.loadAddress = 0x900000;
    module.endAddress = 0x901000;
    CHECK(dbg.moduleSections(module).empty());
}
