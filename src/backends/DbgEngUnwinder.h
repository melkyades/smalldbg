#pragma once

#include "DbgEngBackend.h"
#include "../../include/smalldbg/NativeUnwinder.h"

namespace smalldbg {

/** Native frames, unwound by the engine's own stack walk. It follows the
 *  compiler's unwind data, so it finds callers a frame-pointer chain cannot:
 *  those of functions without a frame pointer, and of frames stopped in a
 *  prologue. One frame at a time it unwinds as NativeUnwinder does.
 **/
class DbgEngUnwinder : public NativeUnwinder {
public:
    explicit DbgEngUnwinder(const DbgEngBackend& backend) : backend(backend) {}

    std::vector<StackFrame> unwindRun(const Registers& regs, size_t maxFrames,
                                      Debugger* /*debugger*/) override {
        return backend.walkStack(regs.ip(), regs.sp(), regs.fp(), maxFrames);
    }

private:
    const DbgEngBackend& backend;
};

} // namespace smalldbg
