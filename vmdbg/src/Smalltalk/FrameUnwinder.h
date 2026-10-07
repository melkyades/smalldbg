#pragma once

#include <smalldbg/StackUnwinder.h>
#include <smalldbg/StackTrace.h>

#include <cstdint>
#include <string>

namespace smalltalk {

/** Where a VM keeps the things every Smalltalk frame has, as byte offsets from
 *  the frame pointer. A dialect that does not keep one of these leaves it at
 *  `absent`. **/
struct FrameLayout {
    static constexpr int absent = INT32_MIN;

    int callerFrame{0};    // saved frame pointer of the caller
    int returnAddress{4};  // where the frame returns to
    int self{absent};      // the receiver
    int method{absent};    // the CompiledMethod being run
    int context{absent};
    int firstArgument{8};  // arguments start here, growing away from the frame
};

/** Walking the frames a Smalltalk VM builds.
 *
 *  Every dialect links its frames the same way -- a saved frame pointer and a
 *  return address at a fixed offset -- so the walk, the sanity checks and the
 *  recovery from a broken link are written once. A dialect says where its
 *  frames live and how to name one. **/
class FrameUnwinder : public smalldbg::StackUnwinder {
public:
    /** Returns true when the frame at `ip` belongs to this VM: it is running
     *  code the VM generated. **/
    bool canUnwind(smalldbg::Address ip, const smalldbg::Registers& regs,
                    smalldbg::Debugger* debugger) override;

    smalldbg::Status unwind(smalldbg::StackFrame& frame,
                            smalldbg::Debugger* debugger) override;

protected:
    // ---- what a dialect must answer ---------------------------------------

    virtual const FrameLayout& layout() const = 0;

    /** Returns true for an address inside the VM's own generated code. **/
    virtual bool isVMCode(uint64_t ip, smalldbg::Debugger* debugger) const = 0;

    /** Returns true for an address on the stack this VM runs Smalltalk on. **/
    virtual bool isVMStack(uint64_t address) const = 0;

    /** Bytes per stack slot, which is the VM's pointer width. **/
    virtual size_t slotSize() const = 0;

    // ---- built on the above ------------------------------------------------

    /** The caller link and return address stored in the frame at
     *  `framePointer`. Returns false when either cannot be read. **/
    bool readFrameLink(uint64_t framePointer, uint64_t& callerFrame,
                       uint64_t& returnAddress, smalldbg::Debugger* debugger) const;

    /** A frame link is only usable if the caller sits further up the same
     *  stack. When a VM stub leaves something else in that slot -- a heap
     *  value left by a send that missed, a frame a primitive overwrote --
     *  following it walks off the stack and the backtrace ends there. Scanning
     *  forward for the next slot that does look like a frame recovers the rest
     *  of the walk. Returns false when no such slot is found. **/
    bool resyncFrame(uint64_t framePointer, uint64_t& callerFrame,
                     uint64_t& returnAddress, smalldbg::Debugger* debugger) const;

    /** How far to scan before giving up. A frame larger than this is a sign the
     *  link is not recoverable, not that the scan was too short. **/
    static constexpr uint32_t maxResyncSlots = 256;
};

} // namespace smalltalk
