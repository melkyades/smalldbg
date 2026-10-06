#pragma once

#include "Types.h"
#include "StackFrame.h"
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <utility>
#include <cstdint>

namespace smalldbg {

/// Inline frames for a whole stack, keyed by the (ip, fp) of the physical
/// frame that holds them. Asking per frame costs a stack walk each time.
using InlineFrameMap =
    std::map<std::pair<Address, Address>, std::vector<InlineFrameInfo>>;

class Debugger;

// Stack trace collector
class StackTrace {
public:
    StackTrace(const Thread* thread);
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
