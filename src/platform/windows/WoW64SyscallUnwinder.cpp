#include "platform/windows/WoW64SyscallUnwinder.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolProvider.h"

namespace smalldbg {

namespace {

// Returns true for the addresses Windows gives a WoW64 thread in a system
// call: the low half is 0x0002, below 0x10000000.
bool isSyscallAddress(uint32_t ip) {
    return (ip & 0xFFFF) == 0x0002 && ip < 0x10000000;
}

// Returns the return address at the top of a 32-bit stack, or 0 when it
// cannot be read.
uint32_t returnAddressAt(Debugger* debugger, uint32_t sp) {
    uint32_t address = 0;
    if (debugger->readMemory(sp, &address, 4) != Status::Ok) return 0;
    return address;
}

} // namespace

// Only a 64-bit debugger reading a 32-bit target sees WoW64 frames.
bool WoW64SyscallUnwinder::canUnwind(Address ip, const Registers& regs,
                                     Debugger* /*debugger*/) {
    return sizeof(void*) == 8 && regs.pointerSize() == 4
           && isSyscallAddress(static_cast<uint32_t>(ip));
}

// The system call was a bare call, so no frame pointer was saved: the caller
// resumes at the return address on the stack.
Status WoW64SyscallUnwinder::unwind(StackFrame& frame, Debugger* debugger) {
    auto& regs = frame.registers;
    uint32_t returnAddress = returnAddressAt(debugger, regs.x86.esp);
    if (returnAddress == 0) return Status::Error;
    regs.x86.eip = returnAddress;
    regs.x86.esp += 4;
    return Status::Ok;
}

// The frame is named after the routine that made the system call.
void WoW64SyscallUnwinder::process(StackFrame& frame, Debugger* debugger) {
    frame.moduleName = "WoW64";
    frame.functionName = "syscall";
    uint32_t returnAddress =
        returnAddressAt(debugger, static_cast<uint32_t>(frame.sp()));
    if (returnAddress == 0) return;
    auto* symbols = debugger->getSymbolProvider();
    auto caller = symbols->getSymbolByAddress(returnAddress);
    if (caller && !caller->name.empty())
        frame.functionName = "syscall [" + caller->name + "]";
}

} // namespace smalldbg
