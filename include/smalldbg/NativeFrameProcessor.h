#pragma once

#include "StackFrameProcessor.h"

namespace smalldbg {

// Default frame processor for native C/C++ frames.
// Uses the debugger backend for platform-specific unwinding (.pdata / DWARF),
// falling back to manual frame-pointer walking.
// Always last in the processor chain — accepts any frame.
class NativeFrameProcessor : public StackFrameProcessor {
public:
    // Accepts any frame (this is the fallback processor)
    bool canProcess(Address ip, const Registers& regs, Debugger* debugger) override;
    
    // Recover caller registers via platform unwind tables, then manual fallback
    Status unwind(StackFrame& frame, Debugger* debugger) override;
    
    // Fill in symbol, module, source location, and local variables
    void process(StackFrame& frame, Debugger* debugger) override;
};

} // namespace smalldbg
