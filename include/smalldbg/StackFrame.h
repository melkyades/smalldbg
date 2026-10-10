#pragma once

#include "Arch.h"
#include "Types.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smalldbg {

class Thread;
class StackUnwinder;

/** A function the compiler folded into another function's code. The debug
 *  info records the call site, so a single physical frame can stand for
 *  several logical calls. **/
struct InlineFrameInfo {
    std::string name;
    std::string moduleName;
    uint64_t offset{0};   // displacement within the inlined function
};

/** Data an unwinder attaches to the frames it produces. Each unwinder derives
 *  its own; clients cast it based on the frame's unwinder. **/
struct FrameMetadata {
    virtual ~FrameMetadata() = default;
};

struct StackFrame {
    Registers registers;
    bool hasRegisters = false;
    // Unwinding recovers a caller's ip, sp and fp only; the frames the thread
    // stopped in have every register.
    bool allRegisters = false;

    const Thread* thread{nullptr};

    StackUnwinder* unwinder{nullptr};

    // Unwinder-specific metadata (null for unwinders that don't set it)
    std::unique_ptr<FrameMetadata> metadata;

    // Previous frame in the trace (towards the top of the stack / most recent call)
    StackFrame* prev{nullptr};

    Address ip() const { return registers.ip(); }
    Address fp() const { return registers.fp(); }
    Address sp() const { return registers.sp(); }
    void setIp(Address v) { registers.setIp(v); }
    void setFp(Address v) { registers.setFp(v); }
    void setSp(Address v) { registers.setSp(v); }

    /** Returns the frame's registers, leaving empty the ones it does not
     *  know. **/
    std::vector<RegisterValue> registerValues() const;

    std::string functionName;
    std::string moduleName;
    uint64_t functionOffset{0};
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
