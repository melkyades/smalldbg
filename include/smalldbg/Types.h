// small, common types for SmallDBG
#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include "arch/X86Registers.h"
#include "arch/X64Registers.h"
#include "arch/ARM64Registers.h"
#include "Arch.h"

namespace smalldbg {

enum class Mode {
    External,   // attach to an external process
    InProcess,  // operate inside the target process (helper thread)
};

enum class Status {
    Ok,
    Error,
    NotAttached,
    AlreadyAttached,
    NotFound,
    NotSupported
};

enum class StopReason {
    None,              // Not stopped / running
    ProcessCreated,    // Process created successfully (launch only)
    ThreadCreated,     // Thread created
    ModuleLoaded,      // Module/DLL loaded
    ModuleUnloaded,    // Module/DLL unloaded
    InitialBreakpoint, // Initial process loader breakpoint
    Breakpoint,        // Hit a user breakpoint
    SingleStep,        // Single-step completed
    Exception,         // Exception/signal
    ProcessExit        // Process terminated
};

using Address = uint64_t;
using ThreadId = uint64_t;

struct Breakpoint {
    Address addr{0};
    bool enabled{true};
    std::string name;
};

/// Information about a loaded module (executable or shared library).
struct ModuleInfo {
    std::string path;         // File path on disk
    std::string shortName;    // Filename component only
    Address loadAddress{0};   // Runtime load address
    Address endAddress{0};    // Upper bound of text segment
    Address slide{0};         // ASLR slide (loadAddress - preferredBase)
    uint64_t symbolCount{0};  // Number of resolved symbols
};

struct Registers {
    const smalldbg::Arch* arch{X64::instance()};
    X86Registers x86{};
    X64Registers x64{};
    ARM64Registers arm64{};

    // Convenience accessors delegating to the arch
    Address ip() const { return arch->ip(*this); }
    Address fp() const { return arch->fp(*this); }
    Address sp() const { return arch->sp(*this); }
    void setIp(Address v) { arch->setIp(*this, v); }
    void setFp(Address v) { arch->setFp(*this, v); }
    void setSp(Address v) { arch->setSp(*this, v); }
    size_t pointerSize() const { return arch->pointerSize(); }
};

enum class VariableLocation {
    Unknown,
    Register,       // In a register
    Memory,         // At a memory address
    FrameRelative,  // Relative to frame pointer (rbp + offset)
    StackRelative   // Relative to stack pointer (rsp + offset)
};

struct StackFrame;

struct LocalVariable {
    std::string name;
    std::string typeName;
    uint64_t size{0};
    VariableLocation locationType{VariableLocation::Unknown};
    int64_t offset{0};      // Offset from base (rbp/rsp) or register number
    Address address{0};     // Absolute address if locationType == Memory
    const StackFrame* frame{nullptr};  // Back-reference to containing frame
    
    // Read the value of this variable from its frame
    // Returns std::nullopt if the value cannot be read
    std::optional<uint64_t> getValue() const;
    
    // Get the location as a human-readable string (e.g., "rcx", "rbp-8", "addr=0x1234")
    std::string getLocationString() const;
    
    // Print this variable to an output stream
    void print(std::ostream& os) const;
};

} // namespace smalldbg
