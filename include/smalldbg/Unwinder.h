#pragma once

#include "Types.h"

namespace smalldbg {

class Debugger;

// Interface for stack unwinding strategies
// Different runtimes (C/C++, VM bytecode, etc.) can provide their own unwinders
class Unwinder {
public:
    virtual ~Unwinder() = default;
    
    // Check if this unwinder can handle unwinding from the given instruction pointer
    // Returns true if the IP belongs to code that this unwinder understands
    virtual bool canUnwind(Address ip, Debugger* debugger) = 0;
    
    // Unwind one frame: given current registers, recover caller's registers
    // Returns Ok if unwinding succeeded, error otherwise
    virtual Status unwind(Registers& regs, Debugger* debugger) = 0;
};

} // namespace smalldbg
