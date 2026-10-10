#include "smalldbg/NativeUnwinder.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

bool NativeUnwinder::canUnwind(Address ip, const Registers& regs, Debugger* debugger) {
    return true;
}

Status NativeUnwinder::unwind(StackFrame& frame, Debugger* debugger) {
    auto& regs = frame.registers;
    Address origIp = regs.ip();
    Address origFp = regs.fp();

    // The backend's own unwinding first.
    Status status = debugger->recoverCallerRegisters(regs);
    if (status == Status::Ok) {
        if (regs.ip() != origIp || regs.fp() != origFp)
            return Status::Ok;
        // The backend found no caller; try the frame pointer.
        regs.setIp(origIp);
        regs.setFp(origFp);
    }

    // Fallback to manual frame-pointer walking
    Address bp = regs.fp();
    size_t ptrSize = regs.pointerSize();

    Address nextBp = 0;
    Address nextIp = 0;
    if (debugger->readMemory(bp, &nextBp, ptrSize) != Status::Ok)
        return Status::Error;
    if (debugger->readMemory(bp + ptrSize, &nextIp, ptrSize) != Status::Ok)
        return Status::Error;

    if (nextBp <= bp)
        return Status::Error;

    regs.setIp(nextIp);
    regs.setFp(nextBp);
    regs.setSp(nextBp + 2 * ptrSize);
    return Status::Ok;
}

void NativeUnwinder::process(StackFrame& frame, Debugger* debugger) {
    SymbolProvider* symbols = debugger->getSymbolProvider();
    auto symbol = symbols->getSymbolByAddress(frame.ip());

    if (symbol) {
        frame.functionName = symbol->name;
        frame.moduleName = symbol->moduleName;
        frame.functionOffset = frame.ip() - symbol->address;
        frame.functionStart = symbol->address;
    } else {
        frame.functionName = "<unknown>";
        frame.moduleName = "<unknown>";
        frame.functionOffset = 0;
    }
}

void NativeUnwinder::resolveDetails(StackFrame& frame, Debugger* debugger) {
    if (frame.detailsResolved) return;
    frame.detailsResolved = true;
    if (frame.functionName.empty() || frame.functionName == "<unknown>") return;
    SymbolProvider* symbols = debugger->getSymbolProvider();
    auto location = symbols->getSourceLocation(frame.ip());
    if (location) {
        frame.sourceFile = location->filename;
        frame.sourceLine = location->line;
    }
    symbols->getLocalVariables(&frame);
}

std::vector<InlineFrameInfo> NativeUnwinder::inlinedAt(const StackFrame& frame,
                                                       Debugger* debugger) {
    return debugger->getInlineFrames(frame.ip(), frame.sp(), frame.fp());
}

} // namespace smalldbg
