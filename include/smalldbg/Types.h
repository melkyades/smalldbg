// small, common types for SmallDBG
#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <vector>
#include "arch/X86Registers.h"
#include "arch/X64Registers.h"
#include "arch/ARM64Registers.h"
#include "Arch.h"

namespace smalldbg {

enum class Mode {
    External,   // attach to an external process
    InProcess,  // operate inside the target process (helper thread)
};

// What a Debugger is built to debug: a process, running or saved in a dump, a
// recorded trace to replay, or a snapshot of memory that never runs.
enum class Debuggee {
    Process,
    Trace,
    Snapshot,
};

enum class Status {
    Ok,
    Error,
    NotAttached,
    AlreadyAttached,
    NotFound,
    NotSupported,
    // The debuggee is running, so the engine cannot serve this. Distinct from
    // a failure: the same call answers normally once the target stops.
    Busy
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
    ProcessExit,       // Process terminated
    EndOfTrace         // TTD trace reached beginning or end
};

/** Returns a short name for `reason` that a person can read, such as "single
 *  step". **/
const char* stopReasonName(StopReason reason);

using Address = uint64_t;
using ThreadId = uint64_t;

/** The exception a target stopped on. **/
struct ExceptionInfo {
    uint32_t code{0};                   // e.g. 0xC0000005 for an access violation
    Address address{0};                 // where it was raised
    uint32_t flags{0};
    std::vector<uint64_t> parameters;
    std::string description;            // the engine's own words, when it has any
};

struct Breakpoint {
    Address addr{0};
    bool enabled{true};
    std::string name;
};

/** A ModuleSection is one section of a loaded module, such as its code or
 *  its data. **/
struct ModuleSection {
    std::string name;
    Address start{0};
    Address end{0};          // exclusive
    bool executable{false};
};

/** A ModuleInfo describes a loaded executable or shared library. **/
struct ModuleInfo {
    std::string path;         // File path on disk
    std::string shortName;    // Filename component only
    std::string symbolFile;   // Symbol file actually in use (PDB path), if any
    std::string symbolType;   // "pdb", "export", "deferred", "none", ...
    Address loadAddress{0};   // Runtime load address
    Address endAddress{0};    // Upper bound of text segment
    Address slide{0};         // ASLR slide (loadAddress - preferredBase)
    uint64_t symbolCount{0};  // Number of resolved symbols

    /** Returns true when the module has a symbol file, rather than only its
     *  export table or nothing loaded yet. When the symbol type is unknown,
     *  any symbols count. **/
    bool hasSymbolFile() const {
        if (symbolType.empty()) return symbolCount > 0;
        return symbolType != "none" && symbolType != "deferred"
            && symbolType != "export";
    }
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
