// Deterministic, process-free unit tests for the Capstone-backed Disassembler.
// These exercise the Arch-driven capstone mode selection without launching a
// target, so they run fast and reliably in CI.
#include <doctest/doctest.h>

#include "smalldbg/Arch.h"
#include "smalldbg/Disassembler.h"

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

TEST_CASE("empty input yields no instructions") {
    Disassembler dis(X64::instance());
    auto insns = dis.disassemble(nullptr, 0, 0);
    CHECK(insns.empty());
}
