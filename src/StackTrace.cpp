#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackFrameProcessor.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

StackTrace::StackTrace(const Thread* t)
    : thread(t) {
}

StackTrace::~StackTrace() {
}

Status StackTrace::unwind(size_t maxFrames) {
    frames.clear();

    Debugger* debugger = thread->getDebugger();

    Registers regs;
    Status status = debugger->getRegisters(thread, regs);
    if (status != Status::Ok)
        return status;

    const auto& processors = debugger->getFrameProcessors();

    Address prevFp = 0;
    while (frames.size() < maxFrames && regs.ip() != 0) {
        // After the first frame, require FP to advance to avoid infinite loops.
        if (!frames.empty() && regs.fp() <= prevFp)
            break;
        prevFp = regs.fp();
        
        // Find the processor that handles this frame
        StackFrameProcessor* processor = nullptr;
        for (const auto& p : processors) {
            if (p->canProcess(regs.ip(), regs, debugger)) {
                processor = p.get();
                break;
            }
        }
        if (!processor)
            break;
        
        // Build the frame
        auto frame = std::make_unique<StackFrame>();
        frame->registers = regs;
        frame->hasRegisters = true;
        frame->thread = thread;
        frame->processor = processor;
        frame->prev = frames.empty() ? nullptr : frames.back().get();
        
        // Let the processor fill in frame description
        processor->process(*frame, debugger);
        
        // Recover caller registers without clobbering the stored frame.
        // unwind() modifies frame->registers in-place, so we save/restore
        // to keep the frame's own register context intact.
        Registers savedRegs = frame->registers;
        Status unwound = processor->unwind(*frame, debugger);
        regs = frame->registers;           // caller state for next iteration
        frame->registers = savedRegs;      // restore this frame's own state
        
        frames.push_back(std::move(frame));
        
        if (unwound != Status::Ok)
            break;
    }
    
    return Status::Ok;
}

void StackTrace::resolveFrameDetails(size_t index, Debugger* debugger) {
    if (index < frames.size() && frames[index]->processor) {
        frames[index]->processor->resolveDetails(*frames[index], debugger);
    }
}

} // namespace smalldbg
