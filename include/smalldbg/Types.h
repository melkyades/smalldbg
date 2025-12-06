// small, common types for SmallDBG
#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include "arch/X64Registers.h"
#include "arch/ARM64Registers.h"

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

enum class Arch {
    X64,
    ARM64,
    RISCV64
};

struct Registers {
    Arch arch{Arch::X64};
    X64Registers x64{};
    ARM64Registers arm64{};
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
