#pragma once

#include "StackUnwinder.h"

namespace smalldbg {

/** The unwinder for native C/C++ frames, and the fallback for any frame no
 *  other unwinder handles, so it is always last in the chain. It asks the
 *  backend for the caller, and follows the frame-pointer chain itself when
 *  the backend cannot say.
 **/
class NativeUnwinder : public StackUnwinder {
public:
    bool canUnwind(Address ip, const Registers& regs, Debugger* debugger) override;

    Status unwind(StackFrame& frame, Debugger* debugger) override;

    // Fill in symbol, module, source location, and local variables
    void process(StackFrame& frame, Debugger* debugger) override;

    // Lazily resolve source location and local variables for a single frame
    void resolveDetails(StackFrame& frame, Debugger* debugger) override;
};

} // namespace smalldbg
