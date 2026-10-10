#pragma once
#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace smalldbg {

class Arch;

/** A DisasmInsn is one decoded instruction, with what it refers to in the
 *  same terms for every architecture. **/
struct DisasmInsn {
    uint64_t address;
    int size;
    std::string bytes;
    std::string text;
    bool isCall{false};  // transfers control to a callee that returns here
    bool isJump{false};  // transfers control without returning, maybe
                         // conditionally
    bool isReturn{false};  // returns to the caller

    // Where a direct branch goes. For a branch through memory it is the
    // address the destination is read from, and targetIsSlot is set. A
    // branch through a register has none.
    std::optional<uint64_t> target;
    bool targetIsSlot{false};

    // A number the instruction names as a value, such as a constant or an
    // address computed relative to the instruction.
    std::optional<uint64_t> immediate;

    // The address of memory the instruction reads or writes, when it is in
    // the encoding rather than in a register.
    std::optional<uint64_t> memory;

    // Memory the instruction reads or writes at an offset from a register,
    // such as [rbx + 0x18], when no index register is added to it.
    struct RegisterOffset {
        std::string base;
        int64_t displacement{0};
    };
    std::optional<RegisterOffset> relative;
};

class Disassembler {
public:
    Disassembler(const Arch* arch_);
    ~Disassembler();
    std::vector<DisasmInsn> disassemble(const uint8_t* code, size_t size, uint64_t address);
private:
    void* handle = nullptr;
    const Arch* arch = nullptr;
    int family = 0;     // Capstone's architecture
    bool wide = true;   // 64-bit mode
};

} // namespace smalldbg
