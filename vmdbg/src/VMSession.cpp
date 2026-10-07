#include "VMSession.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"

namespace vmdbg {

// =========================================================================
// Thread helpers
// =========================================================================

std::shared_ptr<smalldbg::Thread> VMSession::resolveThread(uint64_t threadId) const {
    auto* dbg = getDebugger();
    if (!dbg) return nullptr;
    auto proc = dbg->getProcess();
    if (!proc) return nullptr;
    auto opt = proc->getThread(threadId);
    return opt ? *opt : nullptr;
}

static bool hasFrameOf(smalldbg::Thread& thread, smalldbg::Address function) {
    smalldbg::StackTrace trace(&thread);
    if (trace.unwind(256) != smalldbg::Status::Ok) return false;
    for (const auto& frame : trace.getFrames())
        if (frame->functionStart == function) return true;
    return false;
}

// Frames are matched by where their function starts, which does not depend on
// how a symbol backend spells names. Unwinding a running target blocks in the
// engine until it stops, so only a stopped one is asked.
std::shared_ptr<smalldbg::Thread> VMSession::threadRunning(const std::string& function) const {
    auto* dbg = getDebugger();
    if (!dbg) return nullptr;
    if (runningThreadVersion == dbg->stateVersion()) return runningThread;
    auto process = dbg->getProcess();
    if (!process || !dbg->isStopped()) return nullptr;
    auto symbol = dbg->getSymbolProvider()->getSymbolByName(function);
    if (!symbol) return nullptr;

    runningThreadVersion = dbg->stateVersion();
    runningThread = nullptr;
    for (const auto& thread : process->threads()) {
        if (!hasFrameOf(*thread, symbol->address)) continue;
        runningThread = thread;
        break;
    }
    return runningThread;
}

size_t VMSession::pointerSize() const {
    auto* dbg = getDebugger();
    return dbg ? dbg->arch()->pointerSize() : smalldbg::hostArch()->pointerSize();
}

} // namespace vmdbg
