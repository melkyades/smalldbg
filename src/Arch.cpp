#include "smalldbg/Arch.h"
#include "smalldbg/Types.h"

#include <iterator>

namespace smalldbg {

// X86
Address X86::ip(const Registers& r) const { return r.x86.eip; }
Address X86::fp(const Registers& r) const { return r.x86.ebp; }
Address X86::sp(const Registers& r) const { return r.x86.esp; }
void X86::setIp(Registers& r, Address v) const { r.x86.eip = static_cast<uint32_t>(v); }
void X86::setFp(Registers& r, Address v) const { r.x86.ebp = static_cast<uint32_t>(v); }
void X86::setSp(Registers& r, Address v) const { r.x86.esp = static_cast<uint32_t>(v); }

// X64
Address X64::ip(const Registers& r) const { return r.x64.rip; }
Address X64::fp(const Registers& r) const { return r.x64.rbp; }
Address X64::sp(const Registers& r) const { return r.x64.rsp; }
void X64::setIp(Registers& r, Address v) const { r.x64.rip = v; }
void X64::setFp(Registers& r, Address v) const { r.x64.rbp = v; }
void X64::setSp(Registers& r, Address v) const { r.x64.rsp = v; }

// ARM64
Address ARM64::ip(const Registers& r) const { return r.arm64.pc; }
Address ARM64::fp(const Registers& r) const { return r.arm64.x29_fp; }
Address ARM64::sp(const Registers& r) const { return r.arm64.sp; }
void ARM64::setIp(Registers& r, Address v) const { r.arm64.pc = v; }
void ARM64::setFp(Registers& r, Address v) const { r.arm64.x29_fp = v; }
void ARM64::setSp(Registers& r, Address v) const { r.arm64.sp = v; }

// describeFlags - status register bit names

namespace {

struct FlagBit { uint64_t bit; const char* name; };

std::string namesOfSetBits(uint64_t flags, const FlagBit* bits, size_t count) {
    std::string out;
    for (size_t i = 0; i < count; i++) {
        if (!(flags & bits[i].bit)) continue;
        if (!out.empty()) out += " ";
        out += bits[i].name;
    }
    return out;
}

// x86/x64 EFLAGS/RFLAGS, low to high. Only the bits a debugger user cares
// about; reserved bits and IOPL are left out.
const FlagBit kEflags[] = {
    {0x00000001, "CF"}, {0x00000004, "PF"}, {0x00000010, "AF"},
    {0x00000040, "ZF"}, {0x00000080, "SF"}, {0x00000100, "TF"},
    {0x00000200, "IF"}, {0x00000400, "DF"}, {0x00000800, "OF"},
    {0x00004000, "NT"}, {0x00010000, "RF"}, {0x00020000, "VM"},
    {0x00040000, "AC"}, {0x00080000, "VIF"}, {0x00100000, "VIP"},
    {0x00200000, "ID"},
};

// ARM64 PSTATE condition flags, plus the mode bits worth seeing.
const FlagBit kPstate[] = {
    {0x80000000, "N"}, {0x40000000, "Z"}, {0x20000000, "C"}, {0x10000000, "V"},
    {0x00200000, "SS"}, {0x00100000, "IL"},
    {0x00000100, "D"}, {0x00000080, "A"}, {0x00000040, "I"}, {0x00000020, "F"},
};

} // namespace

std::string X86::describeFlags(uint64_t flags) const {
    return namesOfSetBits(flags, kEflags, std::size(kEflags));
}

std::string X64::describeFlags(uint64_t flags) const {
    return namesOfSetBits(flags, kEflags, std::size(kEflags));
}

std::string ARM64::describeFlags(uint64_t flags) const {
    return namesOfSetBits(flags, kPstate, std::size(kPstate));
}

// readRegisters — double dispatch
void X86::readRegisters(const RegisterReader& reader, Registers& out) const {
    out.arch = this;
    reader.readX86Regs(out.x86);
}
void X64::readRegisters(const RegisterReader& reader, Registers& out) const {
    out.arch = this;
    reader.readX64Regs(out.x64);
}
void ARM64::readRegisters(const RegisterReader& reader, Registers& out) const {
    out.arch = this;
    reader.readARM64Regs(out.arm64);
}

} // namespace smalldbg
