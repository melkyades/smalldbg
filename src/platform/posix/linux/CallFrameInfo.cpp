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
#include <iterator>
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

namespace {

/** Runs call frame instructions on `row`, from the function's address `loc`
 *  until the next row would start past `pc`. `initial` is the row the CIE
 *  sets up, which DW_CFA_restore goes back to. Returns false for an
 *  instruction it does not know, or a CFA given by an expression. **/
bool runInstructions(const std::vector<uint8_t>& code, const CallFrameInfo::Description& d,
                     uint64_t loc, uint64_t pc, const CallFrameInfo::Row& initial,
                     CallFrameInfo::Row& row) {
    using Rule = CallFrameInfo::Rule;
    std::vector<CallFrameInfo::Row> remembered;
    auto set = [&](uint64_t reg, Rule::Kind kind, int64_t value) {
        if (reg < CallFrameInfo::kRegisters) row.rules[reg] = {kind, value};
    };
    auto restore = [&](uint64_t reg) {
        if (reg < CallFrameInfo::kRegisters) row.rules[reg] = initial.rules[reg];
    };
    auto advance = [&](uint64_t delta) {
        loc += delta * d.codeAlignment;
        return loc <= pc;
    };

    EhFrameCursor in(code, 0);
    while (!in.atEnd()) {
        uint8_t op = in.u8();
        uint8_t low = op & 0x3f;
        switch (op & 0xc0) {
        case 0x40: if (!advance(low)) return true; continue;  // DW_CFA_advance_loc
        case 0x80: set(low, Rule::Offset, static_cast<int64_t>(in.uleb()) * d.dataAlignment); continue;
        case 0xc0: restore(low); continue;                     // DW_CFA_restore
        }
        switch (op) {
        case 0x00: break;  // DW_CFA_nop
        case 0x01: loc = in.pointer(d.pointerEncoding, 0); if (loc > pc) return true; break;
        case 0x02: if (!advance(in.u8())) return true; break;
        case 0x03: if (!advance(in.u16())) return true; break;
        case 0x04: if (!advance(in.u32())) return true; break;
        case 0x05: { uint64_t r = in.uleb(); set(r, Rule::Offset, static_cast<int64_t>(in.uleb()) * d.dataAlignment); break; }
        case 0x06: restore(in.uleb()); break;
        case 0x07: set(in.uleb(), Rule::Undefined, 0); break;
        case 0x08: set(in.uleb(), Rule::SameValue, 0); break;
        case 0x09: { uint64_t r = in.uleb(); set(r, Rule::InRegister, static_cast<int64_t>(in.uleb())); break; }
        case 0x0a: remembered.push_back(row); break;  // DW_CFA_remember_state
        case 0x0b:                                    // DW_CFA_restore_state
            if (remembered.empty()) return false;
            row = remembered.back();
            remembered.pop_back();
            break;
        case 0x0c: row.cfaRegister = static_cast<unsigned>(in.uleb()); row.cfaOffset = static_cast<int64_t>(in.uleb()); break;
        case 0x0d: row.cfaRegister = static_cast<unsigned>(in.uleb()); break;
        case 0x0e: row.cfaOffset = static_cast<int64_t>(in.uleb()); break;
        case 0x0f: return false;  // DW_CFA_def_cfa_expression
        case 0x10:                // DW_CFA_expression
        case 0x16: { uint64_t r = in.uleb(); in.skip(in.uleb()); set(r, Rule::Expression, 0); break; }
        case 0x11: { uint64_t r = in.uleb(); set(r, Rule::Offset, in.sleb() * d.dataAlignment); break; }
        case 0x12: row.cfaRegister = static_cast<unsigned>(in.uleb()); row.cfaOffset = in.sleb() * d.dataAlignment; break;
        case 0x13: row.cfaOffset = in.sleb() * d.dataAlignment; break;
        case 0x14: { uint64_t r = in.uleb(); set(r, Rule::ValOffset, static_cast<int64_t>(in.uleb()) * d.dataAlignment); break; }
        case 0x15: { uint64_t r = in.uleb(); set(r, Rule::ValOffset, in.sleb() * d.dataAlignment); break; }
        // DW_CFA_AARCH64_negate_ra_state: the return address is signed from
        // here on. The unwinder clears the signature bits anyway.
        case 0x2d: break;
        case 0x2e: in.uleb(); break;  // DW_CFA_GNU_args_size
        case 0x2f: { uint64_t r = in.uleb(); set(r, Rule::Offset, -static_cast<int64_t>(in.uleb()) * d.dataAlignment); break; }
        default: return false;
        }
    }
    return !in.failed();
}

} // namespace

std::optional<CallFrameInfo::Row> CallFrameInfo::rowAt(uint64_t pc) const {
    auto d = describe(pc);
    if (!d) return std::nullopt;

    Row initial;
    if (!runInstructions(d->initialInstructions, *d, d->start, d->start, initial, initial))
        return std::nullopt;
    Row row = initial;
    if (!runInstructions(d->instructions, *d, d->start, pc, initial, row))
        return std::nullopt;
    row.returnRegister = d->returnRegister;
    return row;
}

namespace {

// Returns the register with DWARF number `reg`, or null when there is none.
uint64_t* dwarfRegister(Registers& regs, unsigned reg) {
    if (regs.arch == X64::instance()) {
        auto& x = regs.x64;
        uint64_t* numbered[] = {&x.rax, &x.rdx, &x.rcx, &x.rbx, &x.rsi, &x.rdi,
                                &x.rbp, &x.rsp, &x.r8, &x.r9, &x.r10, &x.r11,
                                &x.r12, &x.r13, &x.r14, &x.r15, &x.rip};
        return reg < std::size(numbered) ? numbered[reg] : nullptr;
    }
    if (regs.arch == ARM64::instance()) {
        auto& a = regs.arm64;
        uint64_t* numbered[] = {&a.x0, &a.x1, &a.x2, &a.x3, &a.x4, &a.x5, &a.x6,
                                &a.x7, &a.x8, &a.x9, &a.x10, &a.x11, &a.x12,
                                &a.x13, &a.x14, &a.x15, &a.x16, &a.x17, &a.x18,
                                &a.x19, &a.x20, &a.x21, &a.x22, &a.x23, &a.x24,
                                &a.x25, &a.x26, &a.x27, &a.x28, &a.x29_fp,
                                &a.x30_lr, &a.sp};
        return reg < std::size(numbered) ? numbered[reg] : nullptr;
    }
    return nullptr;
}

} // namespace

// The return address of a frame that made a call points past the call, which
// may be the last instruction of the function, so the frame is looked up one
// byte before it.
bool CallFrameInfo::recoverCaller(Registers& regs, bool innermost) const {
    auto row = rowAt(innermost ? regs.ip() : regs.ip() - 1);
    if (!row) return false;
    const uint64_t* base = dwarfRegister(regs, row->cfaRegister);
    if (!base) return false;
    uint64_t cfa = *base + row->cfaOffset;
    // The caller's stack pointer is not below this frame's, as the stack
    // grows down. Rules that say otherwise are wrong, and following them
    // could go round in circles. A leaf function may leave it as it is.
    if (cfa < regs.sp()) return false;

    Registers caller = regs;
    for (unsigned reg = 0; reg < kRegisters; reg++) {
        uint64_t* value = dwarfRegister(caller, reg);
        if (!value) continue;
        const Rule& rule = row->rules[reg];
        switch (rule.kind) {
        case Rule::SameValue:
            break;
        case Rule::Undefined:
            if (reg == row->returnRegister) return false;
            break;
        case Rule::Offset:
            if (!memory(cfa + rule.value, value, sizeof(*value))) return false;
            break;
        case Rule::ValOffset:
            *value = cfa + rule.value;
            break;
        case Rule::InRegister: {
            const uint64_t* from = dwarfRegister(regs, static_cast<unsigned>(rule.value));
            if (!from) return false;
            *value = *from;
            break;
        }
        case Rule::Expression:
            if (reg == row->returnRegister) return false;
            break;
        }
    }

    const uint64_t* returnAddress = dwarfRegister(caller, row->returnRegister);
    if (!returnAddress || *returnAddress == 0) return false;
    caller.setIp(*returnAddress);
    caller.setSp(cfa);
    regs = caller;
    return true;
}

} // namespace smalldbg
