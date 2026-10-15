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

    /** Reads the search table of the ELF image loaded at `base`. Returns
     *  nothing when the image has no .eh_frame_hdr, or it cannot be read. **/
    static std::optional<CallFrameInfo> read(const MemoryReader& memory, uint64_t base);

    /** Returns the address of the FDE for the function that may hold `pc`,
     *  or 0 when the table has none. The FDE says how far its function goes. **/
    uint64_t fdeFor(uint64_t pc) const;

private:
    struct Entry {
        uint64_t start;  // the function's first address
        uint64_t fde;    // where its FDE is
    };

    MemoryReader memory;
    std::vector<Entry> table;  // sorted by start
};

} // namespace smalldbg
