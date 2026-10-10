#pragma once

#include "Types.h"
#include "StackFrame.h"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace smalldbg {

class Debugger;

// Stack trace collector
class StackTrace {
public:
    StackTrace(const Thread* thread);
    /** A trace of frames found some other way than by unwinding, innermost
     *  first, such as the ones a VM saved for a thread it parked. **/
    StackTrace(const Thread* thread, std::vector<std::unique_ptr<StackFrame>> frames);
    ~StackTrace();

    // Unwind the stack
    // maxFrames: maximum number of frames to collect (0 = unlimited)
    Status unwind(size_t maxFrames = 64);

    // Lazily resolve expensive details (source location, locals) for one frame
    void resolveFrameDetails(size_t index, Debugger* debugger);
    
    // Access collected frames
    const std::vector<std::unique_ptr<StackFrame>>& getFrames() const { return frames; }
    size_t getFrameCount() const { return frames.size(); }

private:
    bool appendFramesFrom(Registers& regs, size_t maxFrames);
    bool appendRun(std::vector<StackFrame>& run, StackUnwinder& unwinder,
                   Registers& regs, size_t maxFrames);
    bool appendRunFrames(std::vector<StackFrame>& run, size_t from, size_t to,
                         const Registers& regs, StackUnwinder& unwinder,
                         size_t maxFrames);
    bool appendFrame(StackUnwinder& unwinder, Registers& regs, size_t maxFrames);
    bool atThreadTop() const;
    bool shouldKeepUnwinding(const Registers& regs, const Registers& previous,
                             size_t maxFrames) const;

    // A physical frame can stand for several logical calls when the compiler
    // inlined them. Emit those above it, innermost first, so the frame list
    // matches what the engine's own backtrace shows.
    void appendInlinedFrames(const StackFrame& physical, Address ip,
                             const std::vector<InlineFrameInfo>& inlined,
                             size_t maxFrames);
    std::unique_ptr<StackFrame> inlinedFrameFor(const StackFrame& physical,
                                                Address ip,
                                                const InlineFrameInfo& inlined) const;

    const Thread* thread;
    std::vector<std::unique_ptr<StackFrame>> frames;
};

} // namespace smalldbg
