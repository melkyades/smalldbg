// Deterministic, process-free unit tests for the Capstone-backed Disassembler.
// These exercise the Arch-driven capstone mode selection without launching a
// target, so they run fast and reliably in CI.
#include <doctest/doctest.h>

#include "smalldbg/Arch.h"
#include "smalldbg/Disassembler.h"

#include <vector>

using namespace smalldbg;

TEST_CASE("x64: single-byte nop decodes") {
    Disassembler dis(X64::instance());
    const uint8_t code[] = {0x90}; // nop
    auto insns = dis.disassemble(code, sizeof(code), 0x1000);

    REQUIRE(insns.size() == 1);
    CHECK(insns[0].address == 0x1000);
    CHECK(insns[0].size == 1);
    CHECK(insns[0].text.rfind("nop", 0) == 0);
}

TEST_CASE("x64: mov rbp, rsp decodes as a three-byte instruction") {
    Disassembler dis(X64::instance());
    const uint8_t code[] = {0x48, 0x89, 0xE5}; // mov rbp, rsp
    auto insns = dis.disassemble(code, sizeof(code), 0x2000);

    REQUIRE(insns.size() == 1);
    CHECK(insns[0].size == 3);
    CHECK(insns[0].text.rfind("mov", 0) == 0);
    CHECK(insns[0].bytes == "4889e5");
}

TEST_CASE("x86: 32-bit ret decodes") {
    Disassembler dis(X86::instance());
    const uint8_t code[] = {0xC3}; // ret
    auto insns = dis.disassemble(code, sizeof(code), 0);

    REQUIRE(insns.size() == 1);
    CHECK(insns[0].size == 1);
    CHECK(insns[0].text.rfind("ret", 0) == 0);
}

TEST_CASE("ARM64: ret decodes as a four-byte instruction") {
    Disassembler dis(ARM64::instance());
    const uint8_t code[] = {0xC0, 0x03, 0x5F, 0xD6}; // ret (0xD65F03C0)
    auto insns = dis.disassemble(code, sizeof(code), 0x4000);

    REQUIRE(insns.size() == 1);
    CHECK(insns[0].size == 4);
    CHECK(insns[0].text.rfind("ret", 0) == 0);
}

TEST_CASE("x64: a call is recognised and a jump is not") {
    Disassembler dis(X64::instance());
    const uint8_t call[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // call rel32
    const uint8_t jump[] = {0xEB, 0x00};                   // jmp rel8

    auto calls = dis.disassemble(call, sizeof(call), 0x1000);
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].isCall);

    auto jumps = dis.disassemble(jump, sizeof(jump), 0x1000);
    REQUIRE(jumps.size() == 1);
    CHECK_FALSE(jumps[0].isCall);
}

TEST_CASE("x64: an indirect call is recognised") {
    Disassembler dis(X64::instance());
    const uint8_t code[] = {0xFF, 0xD0}; // call rax
    auto insns = dis.disassemble(code, sizeof(code), 0x1000);

    REQUIRE(insns.size() == 1);
    CHECK(insns[0].isCall);
}

TEST_CASE("ARM64: bl is a call and ret is not") {
    Disassembler dis(ARM64::instance());
    const uint8_t code[] = {0x00, 0x00, 0x00, 0x94,  // bl #0
                            0xC0, 0x03, 0x5F, 0xD6}; // ret
    auto insns = dis.disassemble(code, sizeof(code), 0x4000);

    REQUIRE(insns.size() == 2);
    CHECK(insns[0].isCall);
    CHECK_FALSE(insns[1].isCall);
}

TEST_CASE("a return is recognised on every architecture, and nothing else is") {
    const uint8_t x64[] = {0x90, 0xC3, 0xC2, 0x08, 0x00}; // nop; ret; ret 8
    auto wide = Disassembler(X64::instance()).disassemble(x64, sizeof(x64), 0);
    REQUIRE(wide.size() == 3);
    CHECK_FALSE(wide[0].isReturn);
    CHECK(wide[1].isReturn);
    CHECK(wide[2].isReturn);

    const uint8_t x86[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3}; // call; ret
    auto narrow = Disassembler(X86::instance()).disassemble(x86, sizeof(x86), 0);
    REQUIRE(narrow.size() == 2);
    CHECK_FALSE(narrow[0].isReturn);
    CHECK(narrow[1].isReturn);

    const uint8_t arm64[] = {0x1F, 0x20, 0x03, 0xD5,  // nop
                             0xC0, 0x03, 0x5F, 0xD6}; // ret
    auto arm = Disassembler(ARM64::instance()).disassemble(arm64, sizeof(arm64), 0);
    REQUIRE(arm.size() == 2);
    CHECK_FALSE(arm[0].isReturn);
    CHECK(arm[1].isReturn);
}

TEST_CASE("memory at an offset from a register names the register") {
    const uint8_t x64[] = {0x48, 0x8B, 0x53, 0x18,               // mov rdx, [rbx + 0x18]
                           0x48, 0x8B, 0x04, 0xCB};              // mov rax, [rbx + rcx*8]
    auto wide = Disassembler(X64::instance()).disassemble(x64, sizeof(x64), 0);
    REQUIRE(wide.size() == 2);
    REQUIRE(wide[0].relative);
    CHECK(wide[0].relative->base == "rbx");
    CHECK(wide[0].relative->displacement == 0x18);
    CHECK_FALSE(wide[1].relative);

    const uint8_t arm64[] = {0x20, 0x04, 0x40, 0xF9};            // ldr x0, [x1, #8]
    auto arm = Disassembler(ARM64::instance()).disassemble(arm64, sizeof(arm64), 0);
    REQUIRE(arm.size() == 1);
    REQUIRE(arm[0].relative);
    CHECK(arm[0].relative->base == "x1");
    CHECK(arm[0].relative->displacement == 8);
}

TEST_CASE("empty input yields no instructions") {
    Disassembler dis(X64::instance());
    auto insns = dis.disassemble(nullptr, 0, 0);
    CHECK(insns.empty());
}

namespace {

const Arch* const kX64 = X64::instance();
const Arch* const kX86 = X86::instance();
const Arch* const kARM64 = ARM64::instance();

DisasmInsn decodeOne(const Arch* arch, std::vector<uint8_t> code, uint64_t at) {
    Disassembler dis(arch);
    auto insns = dis.disassemble(code.data(), code.size(), at);
    REQUIRE(insns.size() == 1);
    return insns[0];
}

} // namespace

TEST_CASE("x64: a branch says where it goes, or which slot it reads") {
    auto call = decodeOne(kX64, {0xE8, 0x0B, 0x00, 0x00, 0x00}, 0x1000);
    CHECK(call.isCall);
    CHECK(call.target == uint64_t(0x1010));
    CHECK_FALSE(call.targetIsSlot);

    auto loop = decodeOne(kX64, {0xEB, 0xFE}, 0x1000);
    CHECK(loop.isJump);
    CHECK(loop.target == uint64_t(0x1000));

    auto notEqual = decodeOne(kX64, {0x0F, 0x85, 0x10, 0, 0, 0}, 0x1000);
    CHECK(notEqual.isJump);
    CHECK(notEqual.target == uint64_t(0x1016));

    auto slot = decodeOne(kX64, {0xFF, 0x25, 0x10, 0, 0, 0}, 0x1000);
    CHECK(slot.target == uint64_t(0x1016));
    CHECK(slot.targetIsSlot);

    auto viaRegister = decodeOne(kX64, {0xFF, 0xD0}, 0x1000);
    CHECK(viaRegister.isCall);
    CHECK_FALSE(viaRegister.target);
}

TEST_CASE("x86: an indirect jump's slot is an absolute address") {
    auto slot = decodeOne(kX86, {0xFF, 0x25, 0x00, 0x21, 0x4F, 0x00}, 0x1000);
    CHECK(slot.target == uint64_t(0x4F2100));
    CHECK(slot.targetIsSlot);
}

TEST_CASE("x86: an operand names an address as a value or reads through one") {
    auto value = decodeOne(kX86, {0xB8, 0x00, 0x21, 0x4F, 0x00}, 0x1000);
    CHECK(value.immediate == uint64_t(0x4F2100));
    CHECK_FALSE(value.memory);

    auto read = decodeOne(kX86, {0xA1, 0x00, 0x21, 0x4F, 0x00}, 0x1000);
    CHECK(read.memory == uint64_t(0x4F2100));

    // mov eax, [eax*4 + 0x4f2100]
    auto indexed = decodeOne(kX86, {0x8B, 0x04, 0x85, 0x00, 0x21, 0x4F, 0x00},
                             0x1000);
    CHECK_FALSE(indexed.memory);
}

TEST_CASE("ARM64: a branch says where it goes, and ADR names an address") {
    auto call = decodeOne(kARM64, {0x04, 0x00, 0x00, 0x94}, 0x4000);
    CHECK(call.isCall);
    CHECK(call.target == uint64_t(0x4010));

    auto back = decodeOne(kARM64, {0xFF, 0xFF, 0xFF, 0x17}, 0x4000);
    CHECK(back.isJump);
    CHECK(back.target == uint64_t(0x3FFC));

    auto notEqual = decodeOne(kARM64, {0x41, 0x00, 0x00, 0x54}, 0x4000);
    CHECK(notEqual.isJump);
    CHECK(notEqual.target == uint64_t(0x4008));

    auto viaRegister = decodeOne(kARM64, {0x00, 0x00, 0x1F, 0xD6}, 0x4000);
    CHECK(viaRegister.isJump);
    CHECK_FALSE(viaRegister.target);

    auto address = decodeOne(kARM64, {0x00, 0x01, 0x00, 0x10}, 0x4000);
    CHECK(address.immediate == uint64_t(0x4020));
}
