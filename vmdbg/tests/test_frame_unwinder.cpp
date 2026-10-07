#include <doctest/doctest.h>

#include "Smalltalk/FrameUnwinder.h"

#include <smalldbg/Arch.h>
#include <smalldbg/Debugger.h>
#include <smalldbg/StackFrame.h>

#include <cstdint>
#include <vector>

namespace {

// A made-up VM: 8-byte slots, its code at [0x400000, 0x500000) and its stack
// at [0x8000, 0x8100), each frame holding the caller's frame pointer and then
// the return address.
constexpr uint64_t kStack = 0x8000;
constexpr uint64_t kStackEnd = 0x8100;

class TestUnwinder : public smalltalk::FrameUnwinder {
public:
    void process(smalldbg::StackFrame&, smalldbg::Debugger*) override {}

protected:
    const smalltalk::FrameLayout& layout() const override {
        static const smalltalk::FrameLayout frames{0, 8, smalltalk::FrameLayout::absent,
                                                   smalltalk::FrameLayout::absent,
                                                   smalltalk::FrameLayout::absent, 16};
        return frames;
    }
    bool isVMCode(uint64_t ip, smalldbg::Debugger*) const override {
        return ip >= 0x400000 && ip < 0x500000;
    }
    bool isVMStack(uint64_t address) const override {
        return address >= kStack && address < kStackEnd;
    }
    size_t slotSize() const override { return 8; }
};

// The stack as a snapshot, with the given words at the given addresses.
struct Stack {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(kStackEnd - kStack);
    smalldbg::Debugger dbg{smalldbg::Mode::External, smalldbg::X64::instance(),
                           smalldbg::Debuggee::Snapshot};

    void put(uint64_t address, uint64_t word) {
        for (int i = 0; i < 8; i++)
            bytes[address - kStack + i] = static_cast<uint8_t>(word >> (8 * i));
    }
    void open() {
        REQUIRE(dbg.openSnapshot({smalldbg::SnapshotRegion::fromBytes(kStack, bytes)})
                == smalldbg::Status::Ok);
    }
};

smalldbg::StackFrame frameAt(uint64_t fp) {
    smalldbg::StackFrame frame;
    frame.registers.arch = smalldbg::X64::instance();
    frame.setIp(0x400100);
    frame.setFp(fp);
    frame.setSp(fp);
    return frame;
}

} // namespace

TEST_CASE("a frame of the VM's code is the VM unwinder's to unwind") {
    TestUnwinder unwinder;
    smalldbg::Registers regs;
    CHECK(unwinder.canUnwind(0x401000, regs, nullptr));
    CHECK_FALSE(unwinder.canUnwind(0x7ff000, regs, nullptr));
}

TEST_CASE("a frame unwinds to the caller its link names") {
    Stack stack;
    stack.put(0x8000, 0x8040);
    stack.put(0x8008, 0x401000);
    stack.open();

    TestUnwinder unwinder;
    auto frame = frameAt(0x8000);
    REQUIRE(unwinder.unwind(frame, &stack.dbg) == smalldbg::Status::Ok);
    CHECK(frame.ip() == 0x401000u);
    CHECK(frame.fp() == 0x8040u);
    CHECK(frame.sp() == 0x8010u);
}

TEST_CASE("a broken link is recovered from the next slot that looks like a frame") {
    Stack stack;
    stack.put(0x8040, 0x1234);       // not a frame on the stack
    stack.put(0x8048, 0x402000);
    stack.put(0x8050, 0x8080);       // the next slot that links like a frame
    stack.put(0x8058, 0x403000);
    stack.open();

    TestUnwinder unwinder;
    auto frame = frameAt(0x8040);
    REQUIRE(unwinder.unwind(frame, &stack.dbg) == smalldbg::Status::Ok);
    CHECK(frame.fp() == 0x8080u);
    CHECK(frame.ip() == 0x403000u);
}

TEST_CASE("a frame that cannot be read does not unwind") {
    Stack stack;
    stack.open();

    TestUnwinder unwinder;
    auto outside = frameAt(0x9000);
    CHECK(unwinder.unwind(outside, &stack.dbg) == smalldbg::Status::Error);
    auto nowhere = frameAt(kStackEnd - 8);
    CHECK(unwinder.unwind(nowhere, &stack.dbg) == smalldbg::Status::Error);
}
