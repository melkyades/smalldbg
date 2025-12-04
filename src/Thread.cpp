#include "smalldbg/Thread.h"
#include "smalldbg/Process.h"
#include "backends/Backend.h"

namespace smalldbg {

Thread::Thread(Backend* be, Process* proc, ThreadId tid)
    : backend(be), process(proc), threadId(tid) {
}

Status Thread::getRegisters(Registers& out) const {
    if (!backend) return Status::NotAttached;
    return backend->getRegisters(const_cast<Thread*>(this), out);
}

Address Thread::getInstructionPointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    
    if (regs.arch == Arch::X64) {
        return regs.x64.rip;
    } else if (regs.arch == Arch::ARM64) {
        return regs.arm64.pc;
    }
    
    return 0;
}

Address Thread::getStackPointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    
    if (regs.arch == Arch::X64) {
        return regs.x64.rsp;
    } else if (regs.arch == Arch::ARM64) {
        return regs.arm64.sp;
    }
    
    return 0;
}

Address Thread::getFramePointer() const {
    Registers regs{};
    if (getRegisters(regs) != Status::Ok) return 0;
    
    if (regs.arch == Arch::X64) {
        return regs.x64.rbp;
    } else if (regs.arch == Arch::ARM64) {
        return regs.arm64.x29_fp;
    }
    
    return 0;
}

} // namespace smalldbg
