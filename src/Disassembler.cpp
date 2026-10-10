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
    family = a;
    wide = m == CS_MODE_64;
    if (cs_open(a, m, reinterpret_cast<csh*>(&handle)) != CS_ERR_OK) {
        handle = nullptr;
        return;
    }
    // Instruction groups and operands, which say what an instruction refers
    // to, need the detail pass.
    cs_option(*reinterpret_cast<csh*>(&handle), CS_OPT_DETAIL, CS_OPT_ON);
}

Disassembler::~Disassembler() {
    if (handle) cs_close(reinterpret_cast<csh*>(&handle));
}

namespace {

// Returns the absolute address of an x86 memory operand, when it is one: an
// address with no register, or one relative to the instruction pointer.
std::optional<uint64_t> x86Address(const cs_insn& ins, const x86_op_mem& mem,
                                   bool wide) {
    if (mem.index != X86_REG_INVALID) return {};
    uint64_t disp = static_cast<uint64_t>(mem.disp);
    if (mem.base == X86_REG_RIP || mem.base == X86_REG_EIP)
        return ins.address + ins.size + disp;
    if (mem.base != X86_REG_INVALID) return {};
    return wide ? disp : static_cast<uint32_t>(disp);
}

void readX86(const cs_insn& ins, bool wide, DisasmInsn& out) {
    const cs_x86& x86 = ins.detail->x86;
    for (uint8_t i = 0; i < x86.op_count; i++) {
        const cs_x86_op& op = x86.operands[i];
        if (op.type == X86_OP_IMM && !out.immediate)
            out.immediate = static_cast<uint64_t>(op.imm);
        if (op.type == X86_OP_MEM && !out.memory)
            out.memory = x86Address(ins, op.mem, wide);
    }
}

// An ARM64 instruction names an address only as an immediate: a branch's
// destination, or an address relative to the instruction, as ADR and a
// literal load give it.
void readArm64(const cs_insn& ins, DisasmInsn& out) {
    const cs_arm64& arm64 = ins.detail->arm64;
    for (uint8_t i = 0; i < arm64.op_count; i++)
        if (arm64.operands[i].type == ARM64_OP_IMM)
            out.immediate = static_cast<uint64_t>(arm64.operands[i].imm);
}

// A branch's destination is the address its operand names: a value for a
// direct branch, or memory it reads the destination from.
void readBranch(DisasmInsn& out) {
    if (!out.isCall && !out.isJump) return;
    if (out.immediate) {
        out.target = out.immediate;
        out.immediate.reset();
    } else if (out.memory) {
        out.target = out.memory;
        out.targetIsSlot = true;
        out.memory.reset();
    }
}

} // namespace

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
        DisasmInsn decoded;
        decoded.address = ins.address;
        decoded.size = static_cast<int>(ins.size);
        decoded.bytes = bytes.str();
        decoded.text = std::string(ins.mnemonic) + " " + ins.op_str;
        csh engine = *reinterpret_cast<csh*>(&handle);
        decoded.isCall = cs_insn_group(engine, &ins, CS_GRP_CALL);
        decoded.isJump = cs_insn_group(engine, &ins, CS_GRP_JUMP);
        decoded.isReturn = cs_insn_group(engine, &ins, CS_GRP_RET);
        if (ins.detail) {
            if (family == CS_ARCH_ARM64) readArm64(ins, decoded);
            else readX86(ins, wide, decoded);
            readBranch(decoded);
        }
        out.push_back(std::move(decoded));
    }
    cs_free(insns, count);
    return out;
}

} // namespace smalldbg
