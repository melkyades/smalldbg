#pragma once

#include "Types.h"

namespace smalldbg {

class Debugger;
struct StackFrame;

/** Unwinds the frames of one kind of code, such as native code or a VM's.
 *
 *  A stack trace asks its unwinders in order which one handles a frame, then
 *  has that one find the frame's caller and describe the frame.
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
};

} // namespace smalldbg
