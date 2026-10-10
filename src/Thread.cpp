#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolProvider.h"

namespace smalldbg {

Thread::Thread(Process* proc, ThreadId tid)
    : process(proc), threadId(tid) {
}

Thread::~Thread() = default;

Debugger* Thread::getDebugger() const {
    return process->getDebugger();
}

Status Thread::getRegisters(Registers& out) const {
    return getDebugger()->getRegisters(this, out);
}

Address Thread::getInstructionPointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    return regs.ip();
}

Address Thread::getStackPointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    return regs.sp();
}

Address Thread::getFramePointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    return regs.fp();
}

SymbolProvider* Thread::getSymbolProvider() const {
    return getDebugger()->getSymbolProvider();
}

// A maxFrames of 0 asks for every frame.
static bool covers(size_t unwound, size_t wanted) {
    return unwound == 0 || (wanted != 0 && wanted <= unwound);
}

StackTrace* Thread::getStackTrace(size_t maxFrames) const {
    uint64_t version = getDebugger()->stateVersion();
    if (trace && traceVersion == version && covers(traceFrames, maxFrames))
        return trace.get();

    auto fresh = std::make_unique<StackTrace>(this);
    if (fresh->unwind(maxFrames) != Status::Ok) return nullptr;
    trace = std::move(fresh);
    traceVersion = version;
    traceFrames = maxFrames;
    return trace.get();
}

} // namespace smalldbg
