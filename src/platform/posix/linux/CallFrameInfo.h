// CallFrameInfo — the .eh_frame unwind rules of an ELF image in the target.
#pragma once

#include "../../Platform.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace smalldbg {

/** The call frame information of an ELF image loaded in the target. It says,
 *  for each address of a function, where the caller's registers are, also in
 *  code built without frame pointers. It is read from the target's memory,
 *  through the image's .eh_frame_hdr search table. **/
class CallFrameInfo {
public:
    using MemoryReader = smalldbg_internal::MemoryReader;

    /** What the FDE of one function, and the CIE it shares with others, say. **/
    struct Description {
        uint64_t start{0};  // the function's first address
        uint64_t end{0};    // the address past its last one
        uint64_t codeAlignment{1};
        int64_t dataAlignment{1};
        unsigned returnRegister{0};   // the column of the return address
        uint8_t pointerEncoding{0};   // how the FDE stores addresses
        std::vector<uint8_t> initialInstructions;  // the CIE's, for every function
        std::vector<uint8_t> instructions;         // the FDE's
    };

    /** Where one of the caller's registers is. **/
    struct Rule {
        enum Kind {
            SameValue,   // the function did not change it
            Undefined,   // not known; for the return address, the stack ends
            Offset,      // saved at CFA + value
            ValOffset,   // is CFA + value
            InRegister,  // is in register `value`
            Expression,  // given by a DWARF expression, which is not followed
        };
        Kind kind{SameValue};
        int64_t value{0};
    };

    // x86-64 numbers its registers 0 to 16, AArch64 0 to 32.
    static constexpr unsigned kRegisters = 33;

    /** The rules at one address of a function. The CFA is the stack pointer
     *  the caller had before the call: a register plus an offset. **/
    struct Row {
        unsigned cfaRegister{0};
        int64_t cfaOffset{0};
        std::array<Rule, kRegisters> rules{};
        unsigned returnRegister{0};  // the column of the return address
    };

    /** Reads the search table of the ELF image loaded at `base`. Returns
     *  nothing when the image has no .eh_frame_hdr, or it cannot be read. **/
    static std::optional<CallFrameInfo> read(const MemoryReader& memory, uint64_t base);

    /** Returns the address of the FDE for the function that may hold `pc`,
     *  or 0 when the table has none. The FDE says how far its function goes. **/
    uint64_t fdeFor(uint64_t pc) const;

    /** Returns what the FDE of the function holding `pc` says, or nothing when
     *  no FDE covers `pc` or it cannot be read. **/
    std::optional<Description> describe(uint64_t pc) const;

    /** Returns the rules at `pc`, or nothing when no FDE covers it, or the
     *  CFA there is given by a DWARF expression, which is not followed. **/
    std::optional<Row> rowAt(uint64_t pc) const;

    /** Sets `regs` to the caller's registers, by the rules at their ip.
     *  `innermost` says they are those of the frame the thread stopped in,
     *  whose ip is not a return address. Returns false when the rules do not
     *  say where the caller is, or say the stack ends here. **/
    bool recoverCaller(Registers& regs, bool innermost) const;

private:
    struct Entry {
        uint64_t start;  // the function's first address
        uint64_t fde;    // where its FDE is
    };

    bool readEntry(uint64_t address, std::vector<uint8_t>& bytes) const;
    bool readCie(uint64_t address, Description& out, bool& hasAugmentationData) const;

    MemoryReader memory;
    std::vector<Entry> table;  // sorted by start
};

} // namespace smalldbg
