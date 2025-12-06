#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Unwinder.h"
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
    Status status = debugger->getRegisters(thread, regs);
    if (status != Status::Ok) {
        return status;
    }

    // Walk the stack using frame pointers and restore registers at each frame
    // This assumes frame pointers are used (-fno-omit-frame-pointer)
    while (frames.size() < maxFrames && regs.x64.rip != 0 && regs.x64.rbp != 0) {
        // Create the frame
        auto frame = std::make_unique<StackFrame>();
        frame->registers = regs;
        frame->hasRegisters = true;
        frame->thread = thread;
        
        // Let processFrame enrich the frame with symbols, source info, etc.
        if (!processFrame(*frame, symbols)) {
            break;
        }
        
        // Add to collection (frame pointer remains stable in vector)
        frames.push_back(std::move(frame));
        
        // Recover caller's register state
        if (!recoverCallerRegisters(regs, debugger)) {
            break;
        }
    }
    
    return Status::Ok;
}

bool StackTrace::processFrame(StackFrame& frame, SymbolProvider* symbols) {
    // Validate frame
    if (frame.ip() == 0 || frame.fp() == 0) {
        return false;
    }
    
    // Try to resolve symbol information
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
    
    // Try to get source location
    auto location = symbols->getSourceLocation(frame.ip());
    if (location) {
        frame.sourceFile = location->filename;
        frame.sourceLine = location->line;
    }
    
    // Get local variables for this frame (populates frame.localVariables directly)
    symbols->getLocalVariables(&frame);
    
    return true;
}

bool StackTrace::recoverCallerRegisters(Registers& regs, Debugger* debugger) {
    // Try registered unwinders first (e.g., custom unwinders for VM frames)
    const auto& unwinders = debugger->getUnwinders();
    for (const auto& unwinder : unwinders) {
        if (unwinder->canUnwind(regs.x64.rip, debugger)) {
            Status status = unwinder->unwind(regs, debugger);
            if (status == Status::Ok) {
                return true;
            }
        }
    }
    
    // Try to use platform-specific unwinding (Windows .pdata or DWARF)
    Status status = debugger->recoverCallerRegisters(regs);
    
    if (status == Status::Ok) {
        // Backend successfully unwound using platform-specific info
        return true;
    }
    
    // Fallback to manual unwinding
    return manualUnwind(regs, debugger);
}

bool StackTrace::manualUnwind(Registers& regs, Debugger* debugger) {
    Address bp = regs.x64.rbp;
    
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
    
    // Update register values to reflect the unwound state (manual fallback)
    regs.x64.rip = nextIp;
    regs.x64.rbp = nextBp;
    regs.x64.rsp = nextBp + 16; // Approximate - past saved BP and return address
    // Note: Other registers are NOT restored in manual mode
    
    return true;
}

} // namespace smalldbg
