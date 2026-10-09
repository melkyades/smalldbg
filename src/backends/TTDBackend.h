// TTD (Time Travel Debugging) replay backend
#pragma once

#include "DbgEngBackend.h"

namespace smalldbg {

/** TTDBackend replays a recorded TTD trace through the DbgEng engine, so
 *  symbols, memory and stacks work as for a live process. Run control can
 *  also go backwards, and the current thread follows the replay position,
 *  which is why thread selection is overridden. **/
class TTDBackend : public DbgEngBackend {
public:
    TTDBackend(Debugger* dbg, Mode m, const Arch* a) : DbgEngBackend(dbg, m, a) {}

    Status openTrace(const std::string& tracePath) override;
    Status stepBack(Thread* thread) override;
    Status reverseStepOver(Thread* thread) override;
    Status reverseStepOut(Thread* thread) override;
    Status reverseResume() override;
    bool isTTDTrace() const override { return true; }

protected:
    bool selectThread(Thread& thread) const override;
};

/** Returns the pointer size, in bytes, of the process a TTD trace recorded,
 *  or 0 when the file does not start with a header this reads. **/
size_t tracePointerSize(const std::string& tracePath);

} // namespace smalldbg
