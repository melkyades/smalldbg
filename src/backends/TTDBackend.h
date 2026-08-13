// TTD (Time Travel Debugging) replay backend
#pragma once

#include "DbgEngBackend.h"

namespace smalldbg {

/// Replays a recorded TTD trace instead of driving a live process.
///
/// A trace is opened through the same DbgEng engine, so everything about
/// symbols, memory and stacks is inherited. What differs is run control: the
/// timeline can be walked backwards, and the engine's notion of "current
/// thread" is a property of the replay position rather than of a live process,
/// which is why thread selection is overridden here.
class TTDBackend : public DbgEngBackend {
public:
    TTDBackend(Debugger* dbg, Mode m, const Arch* a) : DbgEngBackend(dbg, m, a) {}

    Status openTrace(const std::string& tracePath) override;
    Status stepBack(Thread* thread) override;
    Status reverseStepOver(Thread* thread) override;
    Status reverseResume() override;
    bool isTTDTrace() const override { return true; }

protected:
    bool selectThread(Thread& thread) const override;
};

} // namespace smalldbg
