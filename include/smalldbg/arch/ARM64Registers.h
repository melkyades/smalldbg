#pragma once

#include <cstdint>

namespace smalldbg {

struct ARM64Registers {
    uint64_t x0{0};
    uint64_t x1{0};
    uint64_t x2{0};
    uint64_t x3{0};
    uint64_t x4{0};
    uint64_t x5{0};
    uint64_t x6{0};
    uint64_t x7{0};
    uint64_t x8{0};
    uint64_t x9{0};
    uint64_t x10{0};
    uint64_t x11{0};
    uint64_t x12{0};
    uint64_t x13{0};
    uint64_t x14{0};
    uint64_t x15{0};
    uint64_t x16{0};
    uint64_t x17{0};
    uint64_t x18{0};
    uint64_t x19{0};
    uint64_t x20{0};
    uint64_t x21{0};
    uint64_t x22{0};
    uint64_t x23{0};
    uint64_t x24{0};
    uint64_t x25{0};
    uint64_t x26{0};
    uint64_t x27{0};
    uint64_t x28{0};
    uint64_t x29_fp{0};
    uint64_t x30_lr{0};
    uint64_t sp{0};
    uint64_t pc{0};
};

} // namespace smalldbg
