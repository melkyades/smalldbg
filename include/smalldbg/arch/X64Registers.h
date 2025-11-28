#pragma once

#include <array>
#include <cstdint>

namespace smalldbg {

struct Vec128 {
    uint64_t low{0};
    uint64_t high{0};
};

struct Fp80 {
    std::array<uint8_t, 10> bytes{};
};

struct X64Registers {
    uint64_t rip{0};
    uint64_t rsp{0};
    uint64_t rbp{0};
    uint64_t rflags{0};
    uint64_t rax{0};
    uint64_t rbx{0};
    uint64_t rcx{0};
    uint64_t rdx{0};
    uint64_t rsi{0};
    uint64_t rdi{0};
    uint64_t r8{0};
    uint64_t r9{0};
    uint64_t r10{0};
    uint64_t r11{0};
    uint64_t r12{0};
    uint64_t r13{0};
    uint64_t r14{0};
    uint64_t r15{0};
    uint16_t cs{0};
    uint16_t ds{0};
    uint16_t es{0};
    uint16_t fs{0};
    uint16_t gs{0};
    uint16_t ss{0};
    uint64_t fsBase{0};
    uint64_t gsBase{0};
    uint64_t dr0{0};
    uint64_t dr1{0};
    uint64_t dr2{0};
    uint64_t dr3{0};
    uint64_t dr6{0};
    uint64_t dr7{0};
    uint32_t mxcsr{0};
    std::array<Vec128, 16> xmm{};
    uint16_t fpControl{0};
    uint16_t fpStatus{0};
    uint16_t fpTag{0};
    std::array<Fp80, 8> st{};

    // common aliases
    uint64_t pc{0};
    uint64_t sp{0};
};

} // namespace smalldbg
