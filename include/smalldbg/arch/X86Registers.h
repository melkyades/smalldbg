#pragma once

#include <cstdint>

namespace smalldbg {

// x86 (32-bit) register state
struct X86Registers {
    // General purpose registers
    uint32_t eax{0};
    uint32_t ecx{0};
    uint32_t edx{0};
    uint32_t ebx{0};
    uint32_t esp{0};
    uint32_t ebp{0};
    uint32_t esi{0};
    uint32_t edi{0};
    
    // Instruction pointer
    uint32_t eip{0};
    
    // Flags
    uint32_t eflags{0};
    
    // Segment registers
    uint16_t cs{0};
    uint16_t ss{0};
    uint16_t ds{0};
    uint16_t es{0};
    uint16_t fs{0};
    uint16_t gs{0};
};

} // namespace smalldbg
