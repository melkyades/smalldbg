#pragma once

#include "Types.h"
#include <string>
#include <vector>
#include <cstdint>

namespace smalldbg {

// Represents a single frame in a stack trace
struct StackFrame {
    Address instructionPointer;  // Return address / current IP
    Address framePointer;        // Frame pointer (base pointer)
    Address stackPointer;        // Stack pointer
    std::string functionName;    // Resolved function name (if available)
    std::string moduleName;      // Module containing this frame
    uint64_t functionOffset;     // Offset from function start
    
    // Source location (if available)
    std::string sourceFile;
    uint32_t sourceLine = 0;
};

class Thread;
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
    const std::vector<StackFrame>& getFrames() const { return frames; }
    size_t getFrameCount() const { return frames.size(); }

private:
    const Thread* thread;
    std::vector<StackFrame> frames;
    
    // Process a single stack frame and advance to the next
    // Returns true if should continue unwinding, false to stop
    bool processFrame(Address& ip, Address& bp, Address& sp,
                     Debugger* debugger, SymbolProvider* symbols);
};

} // namespace smalldbg
