#include "VMSession.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"

namespace vmdbg {

// =========================================================================
// Thread helpers
// =========================================================================

std::shared_ptr<smalldbg::Thread> VMSession::primaryThread() const {
    auto* dbg = getDebugger();
    if (!dbg) return nullptr;
    auto proc = dbg->getProcess();
    return proc ? proc->primaryThread() : nullptr;
}

std::shared_ptr<smalldbg::Thread> VMSession::resolveThread(uint64_t threadId) const {
    auto* dbg = getDebugger();
    if (!dbg) return nullptr;
    auto proc = dbg->getProcess();
    if (!proc) return nullptr;
    auto opt = proc->getThread(threadId);
    return opt ? *opt : nullptr;
}

size_t VMSession::pointerSize() const {
    auto* dbg = getDebugger();
    return dbg ? dbg->arch()->pointerSize() : smalldbg::hostArch()->pointerSize();
}

} // namespace vmdbg
