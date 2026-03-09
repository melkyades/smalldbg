#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/SymbolProvider.h"

namespace smalldbg {

Thread::Thread(Process* proc, ThreadId tid)
    : process(proc), threadId(tid) {
}

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

StackTrace* Thread::getStackTrace(size_t maxFrames) const {
    // Create a stack trace and unwind
    StackTrace* stackTrace = new StackTrace(this);
    Status status = stackTrace->unwind(maxFrames);
    
    if (status != Status::Ok) {
        delete stackTrace;
        return nullptr;
    }
    
    return stackTrace;
}

} // namespace smalldbg
