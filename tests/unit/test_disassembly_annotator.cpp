#include <doctest/doctest.h>

#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Disassembler.h"
#include "smalldbg/DisassemblyAnnotator.h"
#include "smalldbg/Snapshot.h"

#include <map>
#include <vector>

using namespace smalldbg;

namespace {

// Names the addresses in `code` and `data`, and nothing else.
struct NamedAddresses : AnnotationSource {
    std::map<Address, std::string> code;
    std::map<Address, std::string> data;

    std::string codeLabel(Address address) const override {
        auto found = code.find(address);
        return found == code.end() ? std::string() : found->second;
    }
    std::string dataLabel(Address address) const override {
        auto found = data.find(address);
        return found == data.end() ? std::string() : found->second;
    }
};

std::vector<uint8_t> littleEndian(uint64_t value, size_t size) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < size; i++)
        bytes.push_back((value >> (8 * i)) & 0xff);
    return bytes;
}

std::vector<AnnotatedInstruction> annotate(const Arch* arch,
                                           const std::vector<uint8_t>& code,
                                           Address at, Debugger& debugger,
                                           const AnnotationSource& names) {
    Disassembler disassembler(arch);
    return DisassemblyAnnotator(debugger, names)
        .annotate(disassembler.disassemble(code.data(), code.size(), at));
}

} // namespace

TEST_CASE("only an address-sized number counts as an address") {
    DisasmInsn small{};
    small.immediate = 0x10;
    CHECK_FALSE(immediateAddressOf(small));

    DisasmInsn large{};
    large.immediate = 0x4F2100;
    large.memory = 0x4F2200;
    CHECK(immediateAddressOf(large) == Address(0x4F2100));
    CHECK(memoryOperandOf(large) == Address(0x4F2200));
}

TEST_CASE("an x64 listing names branch destinations and labels its jumps") {
    Debugger debugger(Mode::External, X64::instance(), Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({SnapshotRegion::fromBytes(
                0x403000, littleEndian(0x405000, 8))})
            == Status::Ok);
    NamedAddresses names;
    names.code[0x401010] = "callee";
    names.code[0x405000] = "through";

    auto listing = annotate(X64::instance(), {
        0x90,                                     // 401000 nop
        0xE8, 0x0A, 0x00, 0x00, 0x00,             // 401001 call 401010
        0xEB, 0xF8,                               // 401006 jmp 401000
        0xFF, 0x25, 0xF2, 0x1F, 0x00, 0x00,       // 401008 jmp [rip+1ff2]
    }, 0x401000, debugger, names);
    REQUIRE(listing.size() == 4);

    CHECK(listing[0].label == "L0x401000");
    CHECK(listing[1].text.find("callee") != std::string::npos);
    CHECK(listing[1].comment == "0x401010");
    CHECK(listing[3].comment == "through");
}

TEST_CASE("an ARM64 listing names branch destinations and labels its jumps") {
    Debugger debugger(Mode::External, ARM64::instance(), Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({SnapshotRegion::fromBytes(
                0x400000, std::vector<uint8_t>(16))})
            == Status::Ok);
    NamedAddresses names;
    names.code[0x400014] = "callee";
    names.data[0x40002c] = "table";

    auto listing = annotate(ARM64::instance(), {
        0x1F, 0x20, 0x03, 0xD5,     // 400000 nop
        0x04, 0x00, 0x00, 0x94,     // 400004 bl 400014
        0xFF, 0xFF, 0xFF, 0x17,     // 400008 b 400004
        0x00, 0x01, 0x00, 0x10,     // 40000c adr x0, 40002c
    }, 0x400000, debugger, names);
    REQUIRE(listing.size() == 4);

    CHECK(listing[1].text == "bl callee");
    CHECK(listing[1].comment == "0x400014");
    CHECK(listing[1].label == "L0x400004");
    CHECK(listing[2].comment.empty());
    CHECK(listing[3].text == "adr x0, table");
    CHECK(listing[3].comment == "0x40002c");
}

TEST_CASE("a number printed in decimal is not taken for an address") {
    Debugger debugger(Mode::External, X86::instance(), Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({SnapshotRegion::fromBytes(
                0x400000, std::vector<uint8_t>(16))})
            == Status::Ok);
    NamedAddresses names;
    names.data[0xFFFFFFFF] = "minus one";
    auto listing = annotate(X86::instance(), {0x6A, 0xFF},  // push -1
                            0x401000, debugger, names);
    REQUIRE(listing.size() == 1);
    CHECK(listing[0].comment.empty());
}

TEST_CASE("a slot read through is named, and what it holds is said") {
    Debugger debugger(Mode::External, X64::instance(), Debuggee::Snapshot);
    REQUIRE(debugger.openSnapshot({SnapshotRegion::fromBytes(
                0x403000, littleEndian(0x405000, 8))})
            == Status::Ok);
    NamedAddresses names;
    names.data[0x403000] = "slot";
    names.data[0x405000] = "target";

    auto listing = annotate(X64::instance(), {
        0x48, 0x8B, 0x04, 0x25, 0x00, 0x30, 0x40, 0x00,  // mov rax, [0x403000]
    }, 0x401000, debugger, names);
    REQUIRE(listing.size() == 1);
    CHECK(listing[0].text == "mov rax, qword ptr [slot]");
    CHECK(listing[0].comment == "[0x403000] -> target (0x405000)");

    names.data.erase(0x405000);
    listing = annotate(X64::instance(), {
        0x48, 0x8B, 0x04, 0x25, 0x00, 0x30, 0x40, 0x00,
    }, 0x401000, debugger, names);
    CHECK(listing[0].comment == "[0x403000] -> 0x405000");
}
