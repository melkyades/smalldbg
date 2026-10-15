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
#include <string>

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

// Reads the CIE or FDE at `address`: the bytes after its length. A length of
// 0xffffffff starts a 64-bit entry, which linkers do not write in .eh_frame.
bool CallFrameInfo::readEntry(uint64_t address, std::vector<uint8_t>& bytes) const {
    uint32_t length = 0;
    if (!memory(address, &length, sizeof(length))) return false;
    if (length == 0 || length == 0xffffffff) return false;
    bytes.resize(length);
    return memory(address + sizeof(length), bytes.data(), bytes.size());
}

// A CIE's augmentation string says what its augmentation data holds. It must
// start with 'z', which gives the data's size, so letters this code does not
// know can be skipped. Older formats, such as GCC's "eh", are not read.
bool CallFrameInfo::readCie(uint64_t address, Description& out,
                            bool& hasAugmentationData) const {
    std::vector<uint8_t> bytes;
    if (!readEntry(address, bytes)) return false;
    EhFrameCursor cie(bytes, address + 4);
    if (cie.u32() != 0) return false;  // a CIE's id is 0
    uint8_t version = cie.u8();
    if (version != 1 && version != 3) return false;

    std::string augmentation;
    for (char letter; (letter = static_cast<char>(cie.u8())) != 0 && !cie.failed();)
        augmentation += letter;
    out.codeAlignment = cie.uleb();
    out.dataAlignment = cie.sleb();
    out.returnRegister = version == 1 ? cie.u8() : static_cast<unsigned>(cie.uleb());

    hasAugmentationData = !augmentation.empty();
    if (hasAugmentationData) {
        if (augmentation[0] != 'z') return false;
        uint64_t size = cie.uleb();
        uint64_t end = cie.here() + size;
        for (char letter : augmentation.substr(1)) {
            if (letter == 'R') out.pointerEncoding = cie.u8();
            else if (letter == 'P') cie.pointer(cie.u8(), 0);  // the personality routine
            else if (letter == 'L') cie.u8();                   // how LSDAs are stored
            else if (letter != 'S' && letter != 'B' && letter != 'G') break;
        }
        if (cie.here() > end) return false;
        cie.skip(end - cie.here());
    }
    out.initialInstructions = cie.rest();
    return !cie.failed();
}

// An FDE points back to its CIE: the offset is from the field itself.
std::optional<CallFrameInfo::Description> CallFrameInfo::describe(uint64_t pc) const {
    uint64_t fde = fdeFor(pc);
    std::vector<uint8_t> bytes;
    if (fde == 0 || !readEntry(fde, bytes)) return std::nullopt;
    EhFrameCursor entry(bytes, fde + 4);

    uint64_t cieField = entry.here();
    uint32_t cieOffset = entry.u32();
    Description out;
    bool hasAugmentationData = false;
    if (cieOffset == 0 || !readCie(cieField - cieOffset, out, hasAugmentationData))
        return std::nullopt;

    out.start = entry.pointer(out.pointerEncoding, 0);
    out.end = out.start + entry.pointer(out.pointerEncoding & 0x0f, 0);
    if (pc < out.start || pc >= out.end) return std::nullopt;
    if (hasAugmentationData) entry.skip(entry.uleb());
    out.instructions = entry.rest();
    if (entry.failed()) return std::nullopt;
    return out;
}

} // namespace smalldbg
