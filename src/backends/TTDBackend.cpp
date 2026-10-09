#include "TTDBackend.h"
#include "smalldbg/Thread.h"

#include <cstdint>
#include <fstream>
#include <string>

namespace smalldbg {

// A trace starts with "TTDLog", and records at 0x68 and 0x70 the lowest and
// highest user addresses of its process. Only a 64-bit process has a highest
// address above 4 GB.
size_t tracePointerSize(const std::string& tracePath) {
    alignas(8) char header[0x78] = {};
    std::ifstream in(tracePath, std::ios::binary);
    if (!in.read(header, sizeof header)) return 0;
    if (std::string(header, 6) != "TTDLog") return 0;

    const uint64_t lowest = *reinterpret_cast<const uint64_t*>(header + 0x68);
    const uint64_t highest = *reinterpret_cast<const uint64_t*>(header + 0x70);
    if (lowest != 0x10000 || highest <= lowest) return 0;
    return highest > 0xFFFFFFFFull ? 8 : 4;
}

// A TTD position is global and encodes the thread executing at it, so
// SetCurrentThreadId does not move the engine; only the command processor's
// "~<id>s" repositions the replay onto a thread's timeline.
bool TTDBackend::selectThread(Thread& thread) const {
    ULONG engineId = 0;
    if (!engineThreadId(thread, engineId)) return false;
    std::string command = "~" + std::to_string(engineId) + "s";
    control->Execute(DEBUG_OUTCTL_IGNORE, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    return true;
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

    // A debugger cannot replay a trace of a wider process, so it is refused
    // before the engine opens it.
    const size_t recorded = tracePointerSize(path);
    if (recorded > hostArch()->pointerSize()) {
        if (log) log("(dbgeng) openTrace: the trace recorded a "
                     + std::to_string(recorded * 8) + "-bit process, which a "
                     + std::to_string(hostArch()->pointerSize() * 8)
                     + "-bit debugger cannot replay");
        return Status::NotSupported;
    }

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

// The engine has no execution status for this step, only its command, which
// stops on the call instruction that entered the frame.
Status TTDBackend::reverseStepOut(Thread* thread) {
    if (!attached) return Status::NotAttached;

    requestStepCommand("g-u", *thread);

    if (log) log("(dbgeng) reverseStepOut requested");
    return Status::Ok;
}

Status TTDBackend::reverseResume() {
    if (!attached) return Status::NotAttached;

    requestResume(DEBUG_STATUS_REVERSE_GO);

    if (log) log("(dbgeng) reverseResume requested");
    return Status::Ok;
}

} // namespace smalldbg
