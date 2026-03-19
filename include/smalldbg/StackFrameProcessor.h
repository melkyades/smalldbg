#pragma once

#include "Types.h"

namespace smalldbg {

class Debugger;
struct StackFrame;

// Interface for stack frame processing strategies.
// Different runtimes (C/C++, VM bytecode, etc.) provide their own processors.
// Each processor can:
//   - claim a frame (canProcess)
//   - unwind it (recover caller registers)
//   - process it (fill in frame description: symbol, module, source, etc.)
class StackFrameProcessor {
public:
    virtual ~StackFrameProcessor() = default;
    
    // Check if this processor handles the frame at the given IP.
    // The full register set is available so implementations can probe the
    // frame at fp to validate ownership (e.g. checking a compiled-method slot).
    virtual bool canProcess(Address ip, const Registers& regs, Debugger* debugger) = 0;
    
    // Unwind one frame: given the current frame, recover caller's registers
    // in frame.registers. The frame's prev pointer and processor allow
    // detecting ABI transitions between different runtimes.
    // Returns Ok if unwinding succeeded, error otherwise.
    virtual Status unwind(StackFrame& frame, Debugger* debugger) = 0;
    
    // Fill in frame description (functionName, moduleName, source, etc.)
    virtual void process(StackFrame& frame, Debugger* debugger) = 0;

    // Lazily resolve expensive details (source location, locals) for a single frame.
    // Default implementation does nothing; subclasses override as needed.
    virtual void resolveDetails(StackFrame& frame, Debugger* debugger) {}
};

} // namespace smalldbg
