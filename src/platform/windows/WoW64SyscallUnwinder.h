#pragma once

#include "smalldbg/StackUnwinder.h"

namespace smalldbg {

/** A WoW64SyscallUnwinder unwinds the frame of a 32-bit x86 thread on 64-bit
 *  Windows that is inside a system call. Windows reports such a thread's
 *  instruction pointer as an address in no module, such as 0x730002, and the
 *  return address is at the stack pointer. The debugger registers it on
 *  Windows; it claims a frame only when a 64-bit debugger reads a 32-bit
 *  target. **/
class WoW64SyscallUnwinder : public StackUnwinder {
public:
    bool canUnwind(Address ip, const Registers& regs,
                   Debugger* debugger) override;
    Status unwind(StackFrame& frame, Debugger* debugger) override;
    void process(StackFrame& frame, Debugger* debugger) override;
};

} // namespace smalldbg
