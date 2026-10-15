// CallFrameInfo — the .eh_frame unwind rules of an ELF image in the target.
#pragma once

#include "../../Platform.h"

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

    /** Reads the search table of the ELF image loaded at `base`. Returns
     *  nothing when the image has no .eh_frame_hdr, or it cannot be read. **/
    static std::optional<CallFrameInfo> read(const MemoryReader& memory, uint64_t base);

    /** Returns the address of the FDE for the function that may hold `pc`,
     *  or 0 when the table has none. The FDE says how far its function goes. **/
    uint64_t fdeFor(uint64_t pc) const;

    /** Returns what the FDE of the function holding `pc` says, or nothing when
     *  no FDE covers `pc` or it cannot be read. **/
    std::optional<Description> describe(uint64_t pc) const;

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
