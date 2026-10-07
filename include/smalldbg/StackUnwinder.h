#pragma once

#include "Types.h"
#include "StackFrame.h"

#include <vector>

namespace smalldbg {

class Debugger;

/** Unwinds the frames of one kind of code, such as native code or a VM's.
 *
 *  A stack trace asks its unwinders, highest priority first, which one handles
 *  a frame, then has that one find the frame's caller and describe the frame.
 **/
class StackUnwinder {
public:
    virtual ~StackUnwinder() = default;

    // Whether this unwinder handles the frame at `ip`. The full register set
    // is there so an implementation can probe the frame at fp to confirm it.
    virtual bool canUnwind(Address ip, const Registers& regs, Debugger* debugger) = 0;

    // Unwind one frame: replace frame.registers with the caller's. The frame's
    // prev pointer and unwinder allow detecting transitions between runtimes.
    // Returns Ok if unwinding succeeded, error otherwise.
    virtual Status unwind(StackFrame& frame, Debugger* debugger) = 0;

    // Fill in the frame's description (functionName, moduleName, source, etc.)
    virtual void process(StackFrame& frame, Debugger* debugger) = 0;

    // Lazily resolve expensive details (source location, locals) for a single frame.
    // Default implementation does nothing; subclasses override as needed.
    virtual void resolveDetails(StackFrame& frame, Debugger* debugger) {}

    // The frames from the one at `regs` on, innermost first, as far as this
    // unwinder can follow them in one go, at most maxFrames. Functions inlined
    // into a frame come just before it, as frames flagged `inlined`. Only ip,
    // sp and fp are set in each frame's registers. Empty for an unwinder that
    // goes one frame at a time, through unwind().
    virtual std::vector<StackFrame> unwindRun(const Registers& regs,
                                              size_t maxFrames,
                                              Debugger* debugger) {
        return {};
    }

    // The functions the compiler inlined at the frame's ip, innermost first.
    virtual std::vector<InlineFrameInfo> inlinedAt(const StackFrame& frame,
                                                   Debugger* debugger) {
        return {};
    }
};

} // namespace smalldbg
