#include "smalldbg/Arch.h"
#include "smalldbg/Types.h"

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
