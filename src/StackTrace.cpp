#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include <iostream>

namespace smalldbg {

StackTrace::StackTrace(const Thread* t)
    : thread(t) {
}

StackTrace::~StackTrace() {
}

Status StackTrace::unwind(size_t maxFrames) {
    frames.clear();

    // Get debugger and symbols from thread
    Debugger* debugger = thread->getDebugger();
    SymbolProvider* symbols = debugger->getSymbolProvider();

    // Get initial register context
    Registers regs;
    Status status = debugger->getRegisters(regs);
    if (status != Status::Ok) {
        return status;
    }

    // Extract x64 registers (assuming X64 for now - simple case)
    Address ip = regs.x64.rip;
    Address bp = regs.x64.rbp;
    Address sp = regs.x64.rsp;
    
    // Walk the stack using frame pointers
    // This is the simple case - assumes frame pointers are used (-fno-omit-frame-pointer)
    while (frames.size() < maxFrames && processFrame(ip, bp, sp, debugger, symbols)) {
        // Continue unwinding
    }
    
    return Status::Ok;
}

bool StackTrace::processFrame(Address& ip, Address& bp, Address& sp,
                              Debugger* debugger, SymbolProvider* symbols) {
    if (ip == 0) {
        return false;
    }
    
    StackFrame frame;
    frame.instructionPointer = ip;
    frame.framePointer = bp;
    frame.stackPointer = sp;
    
    // Try to resolve symbol information
    auto symbol = symbols->getSymbolByAddress(ip);
    if (symbol) {
        frame.functionName = symbol->name;
        frame.moduleName = symbol->moduleName;
        frame.functionOffset = ip - symbol->address;
    } else {
        frame.functionName = "<unknown>";
        frame.moduleName = "<unknown>";
        frame.functionOffset = 0;
    }
    
    // Try to get source location
    auto location = symbols->getSourceLocation(ip);
    if (location) {
        frame.sourceFile = location->filename;
        frame.sourceLine = location->line;
    }
    
    frames.push_back(frame);
    
    // Check if we've reached the end
    if (bp == 0) {
        return false;
    }
    
    // Read the next frame pointer and return address from the stack
    // Stack layout (x64):
    //   [bp + 8] = return address
    //   [bp]     = previous frame pointer
    
    Address nextBp = 0;
    Address nextIp = 0;
    
    Status status = debugger->readMemory(bp, &nextBp, sizeof(Address));
    if (status != Status::Ok) {
        // Can't read stack - stop unwinding
        return false;
    }
    
    status = debugger->readMemory(bp + 8, &nextIp, sizeof(Address));
    if (status != Status::Ok) {
        // Can't read return address - stop unwinding
        return false;
    }
    
    // Sanity checks to prevent infinite loops
    if (nextBp <= bp) {
        // Frame pointer should grow (stack grows down, so addresses increase)
        return false;
    }
    
    // Move to next frame
    ip = nextIp;
    sp = bp + 16; // Approximate - past saved BP and return address
    bp = nextBp;
    
    return true;
}

} // namespace smalldbg
