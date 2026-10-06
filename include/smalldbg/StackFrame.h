#pragma once

#include "Types.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smalldbg {

class Thread;
class StackFrameProcessor;

/** A function the compiler folded into another function's code. The debug
 *  info records the call site, so a single physical frame can stand for
 *  several logical calls. **/
struct InlineFrameInfo {
    std::string name;
    std::string moduleName;
    uint64_t offset{0};   // displacement within the inlined function
};

/** Data a frame processor attaches to the frames it produces. Each processor
 *  derives its own; clients cast it based on the frame's processor. **/
struct FrameMetadata {
    virtual ~FrameMetadata() = default;
};

struct StackFrame {
    // Not all registers may be accurate: only callee-saved registers can be
    // reliably restored during unwinding.
    Registers registers;
    bool hasRegisters = false;

    const Thread* thread{nullptr};

    StackFrameProcessor* processor{nullptr};

    // Processor-specific metadata (null for processors that don't set it)
    std::unique_ptr<FrameMetadata> metadata;

    // Previous frame in the trace (towards the top of the stack / most recent call)
    StackFrame* prev{nullptr};

    Address ip() const { return registers.ip(); }
    Address fp() const { return registers.fp(); }
    Address sp() const { return registers.sp(); }
    void setIp(Address v) { registers.setIp(v); }
    void setFp(Address v) { registers.setFp(v); }
    void setSp(Address v) { registers.setSp(v); }

    std::string functionName;
    std::string moduleName;
    uint64_t functionOffset;
    // Entry point of the function. Not always ip()-functionOffset: a frame
    // stopped in a stub has an ip outside its own code.
    Address functionStart{0};

    // True for a synthesized inline frame: it shares the physical frame's
    // registers, so ip()/fp()/sp() describe the enclosing physical frame.
    bool inlined = false;

    std::string sourceFile;
    uint32_t sourceLine = 0;

    std::vector<LocalVariable> localVariables;

    void print(std::ostream& os, size_t frameNumber) const;
};

} // namespace smalldbg
