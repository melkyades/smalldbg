#include "TTDBackend.h"
#include "smalldbg/Thread.h"

#include <string>

namespace smalldbg {

// A TTD position is global and encodes the thread executing at it, so
// SetCurrentThreadId does not move the engine; only the command processor's
// "~<id>s" repositions the replay onto a thread's timeline.
void TTDBackend::selectThread(Thread& thread) const {
    std::string command = "~" + std::to_string(engineThreadId(thread)) + "s";
    control->Execute(DEBUG_OUTCTL_IGNORE, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
}

// WinDbg Preview's dbgeng.dll has built-in TTD support: it opens .run traces
// via OpenDumpFile and loads the TTD engine from a TTD/ subdirectory next to
// itself, giving us symbols, stacks, registers, memory, breakpoints and
// reverse stepping through the standard COM APIs.
Status TTDBackend::openTrace(const std::string& path) {
    if (attached) {
        if (log) log("(dbgeng) openTrace: already attached, detach first");
        return Status::Error;
    }

    if (log) log("(dbgeng) openTrace: opening " + path);

    if (!loadWinDbgPreviewDbgEng()) {
        if (log) log("(dbgeng) openTrace: no TTD-capable dbgeng.dll found. Install it "
                     "with tools/pack_windbg_dlls.sh (needs WinDbg installed), or unzip "
                     "a bundle from tools/pack_windbg_dlls.sh --zip next to the exe, or "
                     "set SMALLDBG_DBGENG_DIR.");
        return Status::Error;
    }

    if (startSession(InitMode::OpenTrace, path) != Status::Ok) {
        if (log) log("(dbgeng) openTrace: DbgEng OpenDumpFile failed");
        return Status::Error;
    }

    if (log) log("(dbgeng) TTD trace opened via DbgEng: " + path);
    return Status::Ok;
}

Status TTDBackend::stepBack(Thread* thread) {
    if (!attached) return Status::NotAttached;

    requestStep(DEBUG_STATUS_REVERSE_STEP_INTO, *thread);

    if (log) log("(dbgeng) stepBack requested");
    return Status::Ok;
}

Status TTDBackend::reverseStepOver(Thread* thread) {
    if (!attached) return Status::NotAttached;

    requestStep(DEBUG_STATUS_REVERSE_STEP_OVER, *thread);

    if (log) log("(dbgeng) reverseStepOver requested");
    return Status::Ok;
}

Status TTDBackend::reverseResume() {
    if (!attached) return Status::NotAttached;

    requestResume(DEBUG_STATUS_REVERSE_GO);

    if (log) log("(dbgeng) reverseResume requested");
    return Status::Ok;
}

} // namespace smalldbg
