#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/StackUnwinder.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"

namespace smalldbg {

namespace {

// The highest-priority unwinder that handles the frame whose registers are
// `regs`.
StackUnwinder* unwinderFor(const Registers& regs, Debugger* debugger) {
    for (const auto& unwinder : debugger->getUnwinders())
        if (unwinder->canUnwind(regs.ip(), regs, debugger)) return unwinder.get();
    return nullptr;
}

// A frame of a run comes with its ip, sp and fp. Its other registers are taken
// from the frame the run started at.
Registers registersAt(const Registers& start, const StackFrame& frame) {
    Registers regs = start;
    regs.setIp(frame.ip());
    regs.setSp(frame.sp());
    regs.setFp(frame.fp());
    return regs;
}

} // namespace

StackTrace::StackTrace(const Thread* t)
    : thread(t) {
}

StackTrace::~StackTrace() {
}

// Each frame is unwound by the highest-priority unwinder that handles it. One
// that can follow several frames in one go hands back a whole run of them,
// which is cut at the first frame a higher-priority unwinder handles; a run
// that is not cut is the rest of the stack.
Status StackTrace::unwind(size_t maxFrames) {
    frames.clear();

    Registers regs;
    Status status = thread->getDebugger()->getRegisters(thread, regs);
    if (status != Status::Ok)
        return status;

    Registers previous;
    while (shouldKeepUnwinding(regs, previous, maxFrames)) {
        previous = regs;
        if (!appendFramesFrom(regs, maxFrames)) break;
    }
    return Status::Ok;
}

// Appends the frame whose registers are `regs`, or the run of frames starting
// at it. Leaves in `regs` the registers of the frame to go on from; false when
// the stack ends.
bool StackTrace::appendFramesFrom(Registers& regs, size_t maxFrames) {
    Debugger* debugger = thread->getDebugger();
    StackUnwinder* unwinder = unwinderFor(regs, debugger);
    if (!unwinder) return false;

    std::vector<StackFrame> run =
        unwinder->unwindRun(regs, maxFrames - frames.size(), debugger);
    if (!run.empty()) return appendRun(run, *unwinder, regs, maxFrames);
    return appendFrame(*unwinder, regs, maxFrames);
}

// Takes the frames of a run up to the first one a higher-priority unwinder
// handles, and leaves that one in `regs` for it. False when the run is not
// cut, as nothing past it is known. A run does not end there by
// itself: a backend's walk carries on through code it has no unwind data for,
// and what it reports past that point is not the stack.
bool StackTrace::appendRun(std::vector<StackFrame>& run, StackUnwinder& unwinder,
                           Registers& regs, size_t maxFrames) {
    Debugger* debugger = thread->getDebugger();
    const Registers start = regs;
    size_t from = 0;
    for (size_t i = 0; i < run.size(); ++i) {
        if (run[i].inlined) continue;
        Registers here = from == 0 ? start : registersAt(start, run[i]);
        if (from > 0 && unwinderFor(here, debugger) != &unwinder) {
            regs = here;
            return true;
        }
        if (!appendRunFrames(run, from, i + 1, here, unwinder, maxFrames))
            return false;
        from = i + 1;
    }
    return false;
}

// run[from, to) is one physical frame, preceded by the frames inlined into it,
// all of which share its registers.
bool StackTrace::appendRunFrames(std::vector<StackFrame>& run, size_t from,
                                 size_t to, const Registers& regs,
                                 StackUnwinder& unwinder, size_t maxFrames) {
    Debugger* debugger = thread->getDebugger();
    for (size_t i = from; i < to; ++i) {
        if (frames.size() >= maxFrames) return false;
        auto frame = std::make_unique<StackFrame>(std::move(run[i]));
        frame->registers = regs;
        frame->hasRegisters = true;
        frame->thread = thread;
        frame->unwinder = &unwinder;
        frame->prev = frames.empty() ? nullptr : frames.back().get();
        if (!frame->inlined) unwinder.process(*frame, debugger);
        frames.push_back(std::move(frame));
    }
    return true;
}

// One frame, unwound by its unwinder, preceded by the functions inlined at it.
bool StackTrace::appendFrame(StackUnwinder& unwinder, Registers& regs,
                             size_t maxFrames) {
    Debugger* debugger = thread->getDebugger();
    auto frame = std::make_unique<StackFrame>();
    frame->registers = regs;
    frame->hasRegisters = true;
    frame->thread = thread;
    frame->unwinder = &unwinder;
    frame->prev = frames.empty() ? nullptr : frames.back().get();
    unwinder.process(*frame, debugger);

    appendInlinedFrames(*frame, regs.ip(), unwinder.inlinedAt(*frame, debugger),
                        maxFrames);
    frame->prev = frames.empty() ? nullptr : frames.back().get();

    // unwind() writes the caller's registers into the frame, which keeps its own.
    Registers own = frame->registers;
    Status unwound = unwinder.unwind(*frame, debugger);
    regs = frame->registers;
    frame->registers = own;

    frames.push_back(std::move(frame));
    return unwound == Status::Ok;
}

// A null ip does not end the stack: a call through a null pointer leaves one
// with callers above it. A caller identical to its callee does, as unwinding
// it again would only find it again.
bool StackTrace::shouldKeepUnwinding(const Registers& regs,
                                     const Registers& previous,
                                     size_t maxFrames) const {
    if (frames.size() >= maxFrames) return false;
    if (frames.empty()) return true;
    return regs.ip() != previous.ip() || regs.sp() != previous.sp()
           || regs.fp() != previous.fp();
}

std::unique_ptr<StackFrame> StackTrace::inlinedFrameFor(
    const StackFrame& physical, Address ip, const InlineFrameInfo& inlined) const {
    auto synthetic = std::make_unique<StackFrame>();
    synthetic->registers = physical.registers;
    synthetic->hasRegisters = physical.hasRegisters;
    synthetic->thread = thread;
    synthetic->unwinder = physical.unwinder;
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
    if (index < frames.size() && frames[index]->unwinder) {
        frames[index]->unwinder->resolveDetails(*frames[index], debugger);
    }
}

} // namespace smalldbg
