#include "FrameUnwinder.h"

#include <smalldbg/Debugger.h>

namespace smalltalk {

namespace {

uint64_t readSlot(uint64_t address, size_t width, smalldbg::Debugger* debugger,
                  bool& ok) {
    uint64_t value = 0;
    ok = debugger->readMemory(address, &value, width) == smalldbg::Status::Ok;
    return ok ? value : 0;
}

} // namespace

bool FrameUnwinder::canUnwind(smalldbg::Address ip,
                                const smalldbg::Registers& /*regs*/,
                                smalldbg::Debugger* debugger) {
    return isVMCode(ip, debugger);
}

bool FrameUnwinder::readFrameLink(uint64_t framePointer, uint64_t& callerFrame,
                                   uint64_t& returnAddress,
                                   smalldbg::Debugger* debugger) const {
    if (framePointer == 0) return false;

    bool ok = false;
    callerFrame = readSlot(framePointer + layout().callerFrame, slotSize(),
                           debugger, ok);
    if (!ok) return false;
    returnAddress = readSlot(framePointer + layout().returnAddress, slotSize(),
                             debugger, ok);
    return ok;
}

bool FrameUnwinder::resyncFrame(uint64_t framePointer, uint64_t& callerFrame,
                                 uint64_t& returnAddress,
                                 smalldbg::Debugger* debugger) const {
    for (uint32_t slot = 1; slot <= maxResyncSlots; slot++) {
        uint64_t candidate = framePointer + slot * slotSize();
        if (!isVMStack(candidate)) return false;

        uint64_t caller = 0, returned = 0;
        if (!readFrameLink(candidate, caller, returned, debugger)) return false;

        // A return address points at code, never back into the stack, and a
        // caller always sits further up it.
        if (returned == 0 || isVMStack(returned)) continue;
        if (!isVMStack(caller) || caller <= candidate) continue;

        callerFrame = caller;
        returnAddress = returned;
        return true;
    }
    return false;
}

smalldbg::Status FrameUnwinder::unwind(smalldbg::StackFrame& frame,
                                        smalldbg::Debugger* debugger) {
    uint64_t framePointer = frame.fp();
    uint64_t callerFrame = 0;
    uint64_t returnAddress = 0;

    if (!readFrameLink(framePointer, callerFrame, returnAddress, debugger))
        return smalldbg::Status::Error;

    if (!isVMStack(callerFrame) || callerFrame <= framePointer) {
        if (!resyncFrame(framePointer, callerFrame, returnAddress, debugger))
            return smalldbg::Status::Error;
    }

    frame.registers.setIp(returnAddress);
    frame.registers.setFp(callerFrame);
    frame.registers.setSp(framePointer + layout().firstArgument);
    return smalldbg::Status::Ok;
}

// Arguments are pushed left to right, so the last one is nearest the frame.
void FrameUnwinder::readArguments(FrameMetadata& running, uint64_t framePointer,
                                  int count, smalldbg::Debugger* debugger) const {
    running.arguments.assign(count, 0);
    for (int i = 0; i < count; ++i) {
        bool ok = false;
        uint64_t at = framePointer + static_cast<uint64_t>(layout().firstArgument)
                      + static_cast<uint64_t>(i) * slotSize();
        running.arguments[count - 1 - i] = readSlot(at, slotSize(), debugger, ok);
        if (!ok) {
            running.arguments.clear();
            return;
        }
    }
}

} // namespace smalltalk
