#pragma once

#include "Types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace smalldbg {

class Thread;  // Forward declaration
class StackFrameProcessor;  // Forward declaration

// Represents a single frame in a stack trace
struct StackFrame {
    // Register context at this frame (for local variable access)
    // Note: Not all registers may be accurate (only callee-saved registers
    // can be reliably restored during unwinding)
    Registers registers;
    bool hasRegisters = false;   // Whether register context is available
    
    // Back-reference to thread (for memory reads by local variables)
    const Thread* thread{nullptr};
    
    // The processor that handled this frame
    StackFrameProcessor* processor{nullptr};
    
    // Previous frame in the trace (towards the top of the stack / most recent call)
    StackFrame* prev{nullptr};
    
    // Arch-aware accessors — delegate to registers
    Address ip() const { return registers.ip(); }
    Address fp() const { return registers.fp(); }
    Address sp() const { return registers.sp(); }
    void setIp(Address v) { registers.setIp(v); }
    void setFp(Address v) { registers.setFp(v); }
    void setSp(Address v) { registers.setSp(v); }
    
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
};

} // namespace smalldbg
