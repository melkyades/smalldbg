#include "TTDBackend.h"
#include "smalldbg/Thread.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
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

// The engine says where it is as "SEQ:STEP" in hex after one of these.
std::optional<TracePosition> tracePositionIn(const std::string& output) {
    for (const char* key : {"Current position: ", "Setting position: "}) {
        auto at = output.find(key);
        if (at == std::string::npos) continue;
        at += std::string(key).size();
        auto colon = output.find(':', at);
        if (colon == std::string::npos) return std::nullopt;
        try {
            TracePosition position;
            position.sequence = std::stoull(output.substr(at, colon - at), nullptr, 16);
            position.step = std::stoull(output.substr(colon + 1), nullptr, 16);
            return position;
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<TracePosition> TTDBackend::tracePosition() const {
    if (!attached) return std::nullopt;
    return tracePositionIn(executeCommand("!tt"));
}

// The ends are found by going to either end and back, which the engine does
// without running anything.
std::optional<std::pair<TracePosition, TracePosition>> TTDBackend::traceExtent() const {
    if (extent || !attached) return extent;
    auto here = tracePositionIn(executeCommand("!tt"));
    auto first = tracePositionIn(executeCommand("!tt 0"));
    auto last = tracePositionIn(executeCommand("!tt 100"));
    if (here) {
        std::ostringstream back;
        back << "!tt " << std::hex << here->sequence << ":" << here->step;
        executeCommand(back.str());
    }
    if (first && last) extent = std::make_pair(*first, *last);
    return extent;
}

// The engine reports the new position at once but applies the registers that
// go with it only when it next runs a command, so one runs straight after.
Status TTDBackend::seekTo(const std::string& target) {
    if (!attached) return Status::NotAttached;
    auto output = executeCommand("!tt " + target + "; !tt");
    return tracePositionIn(output) ? Status::Ok : Status::Error;
}

Status TTDBackend::seekTrace(const TracePosition& position) {
    std::ostringstream target;
    target << std::hex << position.sequence << ":" << position.step;
    return seekTo(target.str());
}

Status TTDBackend::seekTraceFraction(double percent) {
    std::ostringstream target;
    target << std::clamp(percent, 0.0, 100.0);
    return seekTo(target.str());
}

// The engine's data model lists every execution of an address; the last
// entry's TimeStart is when it last ran.
std::optional<TracePosition> TTDBackend::lastExecution(Address address) const {
    if (!attached) return std::nullopt;
    std::ostringstream query;
    query << "@$cursession.TTD.Memory(0x" << std::hex << address << ", 0x"
          << address + 1 << ", \"e\")";
    auto counted = executeCommand("dx " + query.str() + ".Count()");
    auto colon = counted.rfind(':');
    if (colon == std::string::npos) return std::nullopt;
    unsigned long count = 0;
    try { count = std::stoul(counted.substr(colon + 1), nullptr, 0); } catch (...) {}
    if (count == 0) return std::nullopt;

    auto last = executeCommand("dx " + query.str() + "[" + std::to_string(count - 1) + "]");
    auto at = last.find("TimeStart");
    if (at == std::string::npos) return std::nullopt;
    auto start = last.find(':', at);
    return start == std::string::npos
        ? std::nullopt
        : tracePositionIn("Current position: " + last.substr(start + 1));
}

Status TTDBackend::reverseResume() {
    if (!attached) return Status::NotAttached;

    requestResume(DEBUG_STATUS_REVERSE_GO);

    if (log) log("(dbgeng) reverseResume requested");
    return Status::Ok;
}

} // namespace smalldbg
