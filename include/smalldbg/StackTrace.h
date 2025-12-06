#pragma once

#include "Types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace smalldbg {

class Thread;  // Forward declaration

// Represents a single frame in a stack trace
struct StackFrame {
    // Register context at this frame (for local variable access)
    // Note: Not all registers may be accurate (only callee-saved registers
    // can be reliably restored during unwinding)
    Registers registers;
    bool hasRegisters = false;   // Whether register context is available
    
    // Back-reference to thread (for memory reads by local variables)
    const Thread* thread{nullptr};
    
    // Accessors for convenience (direct access to register values)
    Address& ip() { return registers.x64.rip; }  // Return address / current IP
    const Address& ip() const { return registers.x64.rip; }
    Address& fp() { return registers.x64.rbp; }  // Frame pointer (base pointer)
    const Address& fp() const { return registers.x64.rbp; }
    Address& sp() { return registers.x64.rsp; }  // Stack pointer
    const Address& sp() const { return registers.x64.rsp; }
    
    std::string functionName;    // Resolved function name (if available)
    std::string moduleName;      // Module containing this frame
    uint64_t functionOffset;     // Offset from function start
    
    // Source location (if available)
    std::string sourceFile;
    uint32_t sourceLine = 0;
    
    // Local variables at this frame
    std::vector<LocalVariable> localVariables;
    
    // Print this frame to an output stream
    void print(std::ostream& os, size_t frameNumber) const;
};

class Debugger;
class SymbolProvider;

// Stack trace collector
class StackTrace {
public:
    StackTrace(const Thread* thread);
    ~StackTrace();

    // Unwind the stack
    // maxFrames: maximum number of frames to collect (0 = unlimited)
    Status unwind(size_t maxFrames = 64);
    
    // Access collected frames
    const std::vector<std::unique_ptr<StackFrame>>& getFrames() const { return frames; }
    size_t getFrameCount() const { return frames.size(); }

private:
    const Thread* thread;
    std::vector<std::unique_ptr<StackFrame>> frames;
    
    // Enrich a frame with symbol and source information
    // Returns false if frame is invalid (ip or bp are 0)
    bool processFrame(StackFrame& frame, SymbolProvider* symbols);
    
    // Recover caller's register state (platform-specific or manual)
    // Returns false if unwinding should stop
    bool recoverCallerRegisters(Registers& regs, Debugger* debugger);
    
    // Manual fallback: restore registers using frame pointer
    // Returns false if unwinding should stop
    bool manualUnwind(Registers& regs, Debugger* debugger);
};

} // namespace smalldbg
