// CallFrameInfo — the .eh_frame unwind rules of an ELF image in the target.
//
// The formats are those of the LSB (Linux Standard Base) "Exception Frames"
// chapter: .eh_frame_hdr, then CIEs and FDEs in .eh_frame, whose call frame
// instructions are those of DWARF.

#include "CallFrameInfo.h"
#include "EhFrameCursor.h"

#include <algorithm>
#include <cstring>
#include <elf.h>

namespace smalldbg {

// The image starts with its ELF header. Its program headers say where the
// .eh_frame_hdr segment is, as an address the image was linked at: the image
// moved by as much as its first loaded segment did.
std::optional<CallFrameInfo> CallFrameInfo::read(const MemoryReader& memory, uint64_t base) {
    Elf64_Ehdr header{};
    if (!memory(base, &header, sizeof(header))) return std::nullopt;
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0
        || header.e_ident[EI_CLASS] != ELFCLASS64
        || header.e_phentsize != sizeof(Elf64_Phdr))
        return std::nullopt;

    std::vector<Elf64_Phdr> segments(header.e_phnum);
    if (!memory(base + header.e_phoff, segments.data(),
                segments.size() * sizeof(Elf64_Phdr)))
        return std::nullopt;

    const Elf64_Phdr* first = nullptr;
    const Elf64_Phdr* frames = nullptr;
    for (const auto& segment : segments) {
        if (segment.p_type == PT_LOAD && segment.p_offset == 0 && !first) first = &segment;
        if (segment.p_type == PT_GNU_EH_FRAME) frames = &segment;
    }
    if (!first || !frames) return std::nullopt;

    uint64_t hdrAddress = base - first->p_vaddr + frames->p_vaddr;
    std::vector<uint8_t> bytes(frames->p_memsz);
    if (!memory(hdrAddress, bytes.data(), bytes.size())) return std::nullopt;

    // The table is binary searched, so its entries have one size: a pair of
    // 4-byte offsets from the start of .eh_frame_hdr, which is how linkers
    // write it.
    EhFrameCursor hdr(bytes, hdrAddress);
    uint8_t version = hdr.u8();
    uint8_t framePointerEncoding = hdr.u8();
    uint8_t countEncoding = hdr.u8();
    uint8_t tableEncoding = hdr.u8();
    if (version != 1 || tableEncoding != (DW_EH_PE_datarel | DW_EH_PE_sdata4))
        return std::nullopt;
    hdr.pointer(framePointerEncoding, hdrAddress);
    uint64_t count = hdr.pointer(countEncoding, hdrAddress);

    CallFrameInfo info;
    info.memory = memory;
    for (uint64_t i = 0; i < count && !hdr.failed(); i++) {
        uint64_t start = hdr.pointer(tableEncoding, hdrAddress);
        uint64_t fde = hdr.pointer(tableEncoding, hdrAddress);
        info.table.push_back({start, fde});
    }
    if (hdr.failed() || info.table.empty()) return std::nullopt;
    return info;
}

uint64_t CallFrameInfo::fdeFor(uint64_t pc) const {
    auto after = std::upper_bound(table.begin(), table.end(), pc,
        [](uint64_t address, const Entry& entry) { return address < entry.start; });
    if (after == table.begin()) return 0;
    return std::prev(after)->fde;
}

} // namespace smalldbg
