#pragma once

#include "Types.h"
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <utility>
#include <cstdint>

namespace smalldbg {

class Thread;  // Forward declaration
class StackFrameProcessor;  // Forward declaration

/// A function the compiler folded into another function's code. The debug
/// info records the call site, so a single physical frame can stand for
/// several logical calls; DbgEng's `k` prints these as "(Inline)" rows.
struct InlineFrameInfo {
    std::string name;
    std::string moduleName;
    uint64_t offset{0};   // displacement within the inlined function
};

/// Inline frames for a whole stack, keyed by the (ip, fp) of the physical
/// frame that holds them. Asking per frame costs a stack walk each time.
using InlineFrameMap =
    std::map<std::pair<Address, Address>, std::vector<InlineFrameInfo>>;

/// Processor-specific metadata attached to a frame.
/// Each processor subtype defines its own derived struct
/// (e.g. SmalltalkFrameMetadata).  Clients cast based on
/// the processor pointer.
struct FrameMetadata {
    virtual ~FrameMetadata() = default;
};

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

    // Processor-specific metadata (null for processors that don't set it)
    std::unique_ptr<FrameMetadata> metadata;

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
    // Entry point of the function. Not always ip()-functionOffset: a frame
    // parked in a VM stub has an ip outside its own code.
    Address functionStart{0};

    // True for a synthesized inline frame: it shares the physical frame's
    // registers, so ip()/fp()/sp() describe the enclosing physical frame.
    bool inlined = false;

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

    // Lazily resolve expensive details (source location, locals) for one frame
    void resolveFrameDetails(size_t index, Debugger* debugger);
    
    // Access collected frames
    const std::vector<std::unique_ptr<StackFrame>>& getFrames() const { return frames; }
    size_t getFrameCount() const { return frames.size(); }

private:
    // A physical frame can stand for several logical calls when the compiler
    // inlined them. Emit those above it, innermost first, so the frame list
    // matches what the engine's own backtrace shows.
    void appendInlinedFrames(const StackFrame& physical, Address ip,
                             const std::vector<InlineFrameInfo>& inlined,
                             size_t maxFrames);
    std::unique_ptr<StackFrame> inlinedFrameFor(const StackFrame& physical,
                                                Address ip,
                                                const InlineFrameInfo& inlined) const;

    const Thread* thread;
    std::vector<std::unique_ptr<StackFrame>> frames;
};

} // namespace smalldbg
