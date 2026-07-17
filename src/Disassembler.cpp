#include <sstream>
#include <iomanip>
#include <cstring>

#include <capstone/capstone.h>

#include "smalldbg/Disassembler.h"
#include "smalldbg/Arch.h"

namespace smalldbg {

static void getCapstoneArchMode(const Arch* arch, cs_arch& outArch, cs_mode& outMode) {
    if (!arch) {
        outArch = CS_ARCH_X86;
        outMode = CS_MODE_64;
        return;
    }
    const char* name = arch->name();
    if (std::strcmp(name, "x64") == 0) {
        outArch = CS_ARCH_X86;
        outMode = CS_MODE_64;
    } else if (std::strcmp(name, "ARM64") == 0) {
        outArch = CS_ARCH_ARM64;
        outMode = CS_MODE_ARM;
    } else if (std::strcmp(name, "x86") == 0) {
        outArch = CS_ARCH_X86;
        outMode = CS_MODE_32;
    } else {
        outArch = CS_ARCH_X86;
        outMode = CS_MODE_64;
    }
}

Disassembler::Disassembler(const Arch* arch_) : arch(arch_) {
    cs_arch a; cs_mode m;
    getCapstoneArchMode(arch, a, m);
    if (cs_open(a, m, reinterpret_cast<csh*>(&handle)) != CS_ERR_OK) {
        handle = nullptr;
    }
}

Disassembler::~Disassembler() {
    if (handle) cs_close(reinterpret_cast<csh*>(&handle));
}

std::vector<DisasmInsn> Disassembler::disassemble(const uint8_t* code, size_t size, uint64_t address) {
    std::vector<DisasmInsn> out;
    if (!handle) return out;
    cs_insn* insns = nullptr;
    size_t count = cs_disasm(*reinterpret_cast<csh*>(&handle), code, size, address, 0, &insns);
    for (size_t i = 0; i < count; i++) {
        const cs_insn& ins = insns[i];
        std::ostringstream bytes;
        for (size_t j = 0; j < ins.size; j++) {
            bytes << std::hex << std::setw(2) << std::setfill('0') << (int)ins.bytes[j];
        }
        std::string text = std::string(ins.mnemonic) + " " + ins.op_str;
        out.push_back({ins.address, (int)ins.size, bytes.str(), text});
    }
    cs_free(insns, count);
    return out;
}

} // namespace smalldbg
