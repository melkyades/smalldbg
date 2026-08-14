#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackFrameProcessor.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

namespace {

StackFrameProcessor* processorFor(
    const std::vector<std::unique_ptr<StackFrameProcessor>>& processors,
    Address ip, const Registers& regs, Debugger* debugger) {
    for (const auto& p : processors)
        if (p->canProcess(ip, regs, debugger)) return p.get();
    return nullptr;
}

// The walk covers the frames the engine can follow. A frame past that -- a
// VM's own, unwound by a dialect processor -- is not in the map, and is worth
// one direct question.
std::vector<InlineFrameInfo> inlinedFramesAt(const InlineFrameMap& walked,
                                             const Registers& regs,
                                             Debugger* debugger) {
    auto known = walked.find({regs.ip(), regs.fp()});
    if (known != walked.end()) return known->second;
    return debugger->getInlineFrames(regs.ip(), regs.sp(), regs.fp());
}

} // namespace

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

    // One walk up front answers the inline question for every frame the engine
    // can follow. Frames past that -- a VM's own, unwound by a dialect
    // processor -- are not in it, and fall back to asking one at a time.
    InlineFrameMap inlineFrames =
        debugger->getInlineFrameMap(regs.ip(), regs.sp(), regs.fp());

    Address prevFp = 0;
    while (frames.size() < maxFrames && regs.ip() != 0) {
        // After the first frame, require FP to advance to avoid infinite loops.
        if (!frames.empty() && regs.fp() <= prevFp)
            break;
        prevFp = regs.fp();
        
        StackFrameProcessor* processor =
            processorFor(processors, regs.ip(), regs, debugger);
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

        if (!frame->metadata) {
            appendInlinedFrames(*frame, regs.ip(),
                                inlinedFramesAt(inlineFrames, regs, debugger),
                                maxFrames);
            frame->prev = frames.empty() ? nullptr : frames.back().get();
        }

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

std::unique_ptr<StackFrame> StackTrace::inlinedFrameFor(
    const StackFrame& physical, Address ip, const InlineFrameInfo& inlined) const {
    auto synthetic = std::make_unique<StackFrame>();
    synthetic->registers = physical.registers;
    synthetic->hasRegisters = physical.hasRegisters;
    synthetic->thread = thread;
    synthetic->processor = physical.processor;
    synthetic->prev = frames.empty() ? nullptr : frames.back().get();
    synthetic->inlined = true;
    synthetic->functionName = inlined.name;
    synthetic->moduleName = inlined.moduleName;
    synthetic->functionOffset = inlined.offset;
    synthetic->functionStart = ip - inlined.offset;
    return synthetic;
}

void StackTrace::appendInlinedFrames(const StackFrame& physical, Address ip,
                                     const std::vector<InlineFrameInfo>& inlined,
                                     size_t maxFrames) {
    for (const auto& one : inlined) {
        if (frames.size() >= maxFrames) break;
        frames.push_back(inlinedFrameFor(physical, ip, one));
    }
}

void StackTrace::resolveFrameDetails(size_t index, Debugger* debugger) {
    if (index < frames.size() && frames[index]->processor) {
        frames[index]->processor->resolveDetails(*frames[index], debugger);
    }
}

} // namespace smalldbg
