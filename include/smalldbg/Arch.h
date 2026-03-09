// Architecture abstraction — virtual dispatch for register access
#pragma once

#include <cstdint>
#include <cstddef>

namespace smalldbg {

using Address = uint64_t;
struct Registers;
struct X64Registers;
struct X86Registers;
struct ARM64Registers;

// Interface for reading architecture-specific registers from an engine.
// Backends implement this to bridge engine register state → typed register structs.
class RegisterReader {
public:
    virtual ~RegisterReader() = default;
    virtual void readX64Regs(X64Registers& out) const = 0;
    virtual void readX86Regs(X86Registers& out) const = 0;
    virtual void readARM64Regs(ARM64Registers& out) const = 0;
};

// Base class for architecture-specific register access
class Arch {
public:
    virtual ~Arch() = default;

    // Read instruction pointer, frame pointer, stack pointer from a register set
    virtual Address ip(const Registers& r) const = 0;
    virtual Address fp(const Registers& r) const = 0;
    virtual Address sp(const Registers& r) const = 0;

    // Write instruction pointer, frame pointer, stack pointer into a register set
    virtual void setIp(Registers& r, Address v) const = 0;
    virtual void setFp(Registers& r, Address v) const = 0;
    virtual void setSp(Registers& r, Address v) const = 0;

    // Pointer size in bytes (4 for 32-bit, 8 for 64-bit)
    virtual size_t pointerSize() const = 0;

    // Architecture name (e.g., "x86", "x64", "ARM64")
    virtual const char* name() const = 0;

    // Double-dispatch: read registers from a RegisterReader into a Registers struct.
    // Each subclass calls the reader method matching its architecture.
    virtual void readRegisters(const RegisterReader& reader, Registers& out) const = 0;
};

// x86 (32-bit) architecture
class X86 : public Arch {
public:
    Address ip(const Registers& r) const override;
    Address fp(const Registers& r) const override;
    Address sp(const Registers& r) const override;
    void setIp(Registers& r, Address v) const override;
    void setFp(Registers& r, Address v) const override;
    void setSp(Registers& r, Address v) const override;
    size_t pointerSize() const override { return 4; }
    const char* name() const override { return "x86"; }
    void readRegisters(const RegisterReader& reader, Registers& out) const override;

    static X86* instance() { static X86 inst; return &inst; }
};

// x64 (64-bit) architecture
class X64 : public Arch {
public:
    Address ip(const Registers& r) const override;
    Address fp(const Registers& r) const override;
    Address sp(const Registers& r) const override;
    void setIp(Registers& r, Address v) const override;
    void setFp(Registers& r, Address v) const override;
    void setSp(Registers& r, Address v) const override;
    size_t pointerSize() const override { return 8; }
    const char* name() const override { return "x64"; }
    void readRegisters(const RegisterReader& reader, Registers& out) const override;

    static X64* instance() { static X64 inst; return &inst; }
};

// ARM64 architecture
class ARM64 : public Arch {
public:
    Address ip(const Registers& r) const override;
    Address fp(const Registers& r) const override;
    Address sp(const Registers& r) const override;
    void setIp(Registers& r, Address v) const override;
    void setFp(Registers& r, Address v) const override;
    void setSp(Registers& r, Address v) const override;
    size_t pointerSize() const override { return 8; }
    const char* name() const override { return "ARM64"; }
    void readRegisters(const RegisterReader& reader, Registers& out) const override;

    static ARM64* instance() { static ARM64 inst; return &inst; }
};

} // namespace smalldbg
