// small, common types for SmallDBG
#pragma once

#include <cstdint>
#include <string>
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
    NotFound
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

} // namespace smalldbg
