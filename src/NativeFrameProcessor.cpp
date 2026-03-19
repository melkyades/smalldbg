#include "smalldbg/NativeFrameProcessor.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

bool NativeFrameProcessor::canProcess(Address ip, const Registers& regs, Debugger* debugger) {
    return true;  // fallback — accepts everything
}

Status NativeFrameProcessor::unwind(StackFrame& frame, Debugger* debugger) {
    auto& regs = frame.registers;
    Address origIp = regs.ip();
    Address origFp = regs.fp();
    
    // Try platform-specific unwinding (Windows .pdata or DWARF)
    Status status = debugger->recoverCallerRegisters(regs);
    if (status == Status::Ok) {
        if (regs.ip() != origIp || regs.fp() != origFp)
            return Status::Ok;
        // StackWalk64 didn't advance — fall through to manual
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

void NativeFrameProcessor::process(StackFrame& frame, Debugger* debugger) {
    SymbolProvider* symbols = debugger->getSymbolProvider();
    auto symbol = symbols->getSymbolByAddress(frame.ip());
    
    if (symbol) {
        frame.functionName = symbol->name;
        frame.moduleName = symbol->moduleName;
        frame.functionOffset = frame.ip() - symbol->address;
    } else {
        frame.functionName = "<unknown>";
        frame.moduleName = "<unknown>";
        frame.functionOffset = 0;
    }
}

void NativeFrameProcessor::resolveDetails(StackFrame& frame, Debugger* debugger) {
    if (frame.sourceFile.empty() && !frame.functionName.empty() &&
        frame.functionName != "<unknown>") {
        SymbolProvider* symbols = debugger->getSymbolProvider();
        auto location = symbols->getSourceLocation(frame.ip());
        if (location) {
            frame.sourceFile = location->filename;
            frame.sourceLine = location->line;
        }
        symbols->getLocalVariables(&frame);
    }
}

} // namespace smalldbg
