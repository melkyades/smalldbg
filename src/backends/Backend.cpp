#include "Backend.h"
#include "../../include/smalldbg/Debugger.h"
#include "../../include/smalldbg/Disassembler.h"
#include "../../include/smalldbg/Thread.h"

namespace smalldbg {

namespace {

// The longest instruction on any architecture we disassemble.
constexpr size_t maxInstructionSize = 15;

} // namespace

Status Backend::stepOver(Thread* thread) {
    Address ip = thread->getInstructionPointer();
    uint8_t code[maxInstructionSize];
    if (readMemory(ip, code, sizeof code) != Status::Ok) return step(thread);

    auto insns = debugger->getDisassembler()->disassemble(code, sizeof code, ip);
    if (insns.empty() || !insns[0].isCall) return step(thread);
    return runTo(ip + insns[0].size);
}

Status Backend::stepOut(Thread* thread) {
    return runToFrameReturn(thread, 1);
}

Status Backend::runToFrameReturn(Thread* thread, size_t depth) {
    StackTrace* trace = thread->getStackTrace(depth + 1);
    if (!trace || trace->getFrameCount() <= depth)
        return Status::NotFound;
    return runTo(trace->getFrames()[depth]->ip());
}

Status Backend::runTo(Address address) {
    return debugger->runTo(address, -1);
}

} // namespace smalldbg
