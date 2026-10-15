// EhFrameCursor — reads the values .eh_frame data is made of.
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace smalldbg {

// How a pointer is stored (the low four bits) and what it is relative to
// (the next three bits). DW_EH_PE_omit says there is none.
enum : uint8_t {
    DW_EH_PE_absptr  = 0x00,
    DW_EH_PE_uleb128 = 0x01,
    DW_EH_PE_udata2  = 0x02,
    DW_EH_PE_udata4  = 0x03,
    DW_EH_PE_udata8  = 0x04,
    DW_EH_PE_sleb128 = 0x09,
    DW_EH_PE_sdata2  = 0x0a,
    DW_EH_PE_sdata4  = 0x0b,
    DW_EH_PE_sdata8  = 0x0c,
    DW_EH_PE_pcrel   = 0x10,
    DW_EH_PE_datarel = 0x30,
    DW_EH_PE_omit    = 0xff,
};

/** Reads the values .eh_frame data is made of, from a copy of target memory
 *  that starts at `address` in the target. Once a read runs past the end,
 *  every read gives 0 and failed() is true. **/
class EhFrameCursor {
public:
    EhFrameCursor(const std::vector<uint8_t>& data, uint64_t address)
        : bytes(data), start(address) {}

    bool failed() const { return overrun; }
    bool atEnd() const { return overrun || position >= bytes.size(); }
    uint64_t here() const { return start + position; }

    void skip(uint64_t count) {
        if (count > bytes.size() - position) overrun = true;
        else position += count;
    }

    /** Returns the bytes not read yet. **/
    std::vector<uint8_t> rest() const {
        if (overrun) return {};
        return std::vector<uint8_t>(bytes.begin() + position, bytes.end());
    }

    uint8_t u8() { return static_cast<uint8_t>(fixed(1)); }
    uint16_t u16() { return static_cast<uint16_t>(fixed(2)); }
    uint32_t u32() { return static_cast<uint32_t>(fixed(4)); }
    uint64_t u64() { return fixed(8); }

    uint64_t uleb() {
        uint64_t value = 0;
        for (unsigned shift = 0; ; shift += 7) {
            uint8_t byte = u8();
            if (shift < 64) value |= static_cast<uint64_t>(byte & 0x7f) << shift;
            if (!(byte & 0x80) || overrun) return value;
        }
    }

    int64_t sleb() {
        int64_t value = 0;
        unsigned shift = 0;
        uint8_t byte = 0;
        do {
            byte = u8();
            if (shift < 64) value |= static_cast<int64_t>(byte & 0x7f) << shift;
            shift += 7;
        } while ((byte & 0x80) && !overrun);
        if (shift < 64 && (byte & 0x40)) value |= -(static_cast<int64_t>(1) << shift);
        return value;
    }

    /** Reads a pointer stored as `encoding` says. `dataBase` is what a
     *  DW_EH_PE_datarel pointer is relative to. **/
    uint64_t pointer(uint8_t encoding, uint64_t dataBase) {
        if (encoding == DW_EH_PE_omit) return 0;
        uint64_t field = here();
        uint64_t value = 0;
        switch (encoding & 0x0f) {
        case DW_EH_PE_absptr:  value = u64(); break;
        case DW_EH_PE_uleb128: value = uleb(); break;
        case DW_EH_PE_udata2:  value = u16(); break;
        case DW_EH_PE_udata4:  value = u32(); break;
        case DW_EH_PE_udata8:  value = u64(); break;
        case DW_EH_PE_sleb128: value = static_cast<uint64_t>(sleb()); break;
        case DW_EH_PE_sdata2:  value = static_cast<uint64_t>(static_cast<int16_t>(u16())); break;
        case DW_EH_PE_sdata4:  value = static_cast<uint64_t>(static_cast<int32_t>(u32())); break;
        case DW_EH_PE_sdata8:  value = u64(); break;
        default: overrun = true; return 0;
        }
        switch (encoding & 0x70) {
        case 0: return value;
        case DW_EH_PE_pcrel: return field + value;
        case DW_EH_PE_datarel: return dataBase + value;
        default: overrun = true; return 0;
        }
    }

private:
    uint64_t fixed(size_t size) {
        if (overrun || position + size > bytes.size()) {
            overrun = true;
            return 0;
        }
        uint64_t value = 0;
        std::memcpy(&value, bytes.data() + position, size);  // little endian
        position += size;
        return value;
    }

    const std::vector<uint8_t>& bytes;
    uint64_t start;
    size_t position{0};
    bool overrun{false};
};


} // namespace smalldbg
