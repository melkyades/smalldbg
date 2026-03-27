#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace smalldbg {

class Arch;

struct DisasmInsn {
    uint64_t address;
    int size;
    std::string bytes;
    std::string text;
};

class Disassembler {
public:
    Disassembler(const Arch* arch_);
    ~Disassembler();
    std::vector<DisasmInsn> disassemble(const uint8_t* code, size_t size, uint64_t address);
private:
    void* handle = nullptr;
    const Arch* arch = nullptr;
};

} // namespace smalldbg
