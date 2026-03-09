#pragma once

#include <smalldbg/Debugger.h>
#include <string>
#include <ostream>
#include <cstdint>

namespace egg {

class EggSmallInteger;
class EggHeapObject;

// Egg VM object format constants.
//
// An oop points to the first slot / payload byte.  The header lives
// at negative byte-offsets before the oop.  In memory:
//
//   Address          Size  Content
//   -----------      ----  -------
//   [oop - 16]        4    large size   (only when IsSmall flag is clear)
//   [oop - 12]        4    padding      (only when IsSmall flag is clear)
//   [oop -  8]        2    hash
//   [oop -  6]        1    size         (small size, 0–255)
//   [oop -  5]        1    flags
//   [oop -  4]        4    behavior     (compressed 32-bit, OR with behaviorAddressSpace)
//   [oop]             …    first slot / payload
//
// Slots are 8 bytes (64-bit pointers on ARM64).
// SmallInteger encoding: lowest bit = 1, value = oop >> 1.
struct EggObjectFormat {
    // --- byte offsets from oop (little-endian ARM64) ---
    static constexpr int HASH_OFFSET       = -8;   // uint16_t
    static constexpr int SIZE_OFFSET       = -6;   // uint8_t  (small size)
    static constexpr int FLAGS_OFFSET      = -5;   // uint8_t  (flag bits)
    static constexpr int BEHAVIOR_OFFSET   = -4;   // uint32_t (compressed behavior)
    static constexpr int LARGE_SIZE_OFFSET = -16;  // uint32_t (when not small)

    static constexpr size_t SMALL_HEADER_SIZE = 8;
    static constexpr size_t LARGE_HEADER_SIZE = 16;
    static constexpr size_t SLOT_SIZE         = 8;  // 64-bit

    // --- flag bits (byte at FLAGS_OFFSET) ---
    static constexpr uint8_t FLAG_IS_BYTES    = 0x01;
    static constexpr uint8_t FLAG_IS_ARRAYED  = 0x02;
    static constexpr uint8_t FLAG_IS_NAMED    = 0x04;
    static constexpr uint8_t FLAG_IS_SMALL    = 0x80;

    // SmallInteger tag
    static constexpr uint64_t SMI_TAG = 1;
};

// ---------------------------------------------------------------------------
// EggObject — lightweight value-type representing any Egg oop (tagged pointer).
//
// An Egg oop is either:
//   • a SmallInteger  (lowest bit == 1, value in upper 63 bits), or
//   • a heap pointer  (lowest bit == 0, address of object body).
//
// Carries the raw oop, a debugger pointer, and the behaviorAddressSpace
// needed to decompress 32-bit behavior fields.
// ---------------------------------------------------------------------------
class EggObject {
public:
    EggObject() = default;
    EggObject(uint64_t oop, smalldbg::Debugger* dbg, uint64_t bas)
        : oop_(oop), debugger_(dbg), behaviorAddressSpace_(bas) {}

    // ---- identity ---------------------------------------------------
    uint64_t oop() const { return oop_; }
    bool isValid() const { return debugger_ != nullptr; }
    explicit operator bool() const { return isValid() && oop_ != 0; }
    smalldbg::Debugger* debuggerPtr() const { return debugger_; }
    uint64_t behaviorAddressSpace() const { return behaviorAddressSpace_; }

    // ---- tag tests --------------------------------------------------
    bool isSmallInteger() const { return (oop_ & EggObjectFormat::SMI_TAG) != 0; }
    bool isHeapObject()   const { return !isSmallInteger() && oop_ != 0; }

    // ---- typed views ------------------------------------------------
    EggSmallInteger asSmallInteger() const;   // defined after EggSmallInteger
    EggHeapObject   asHeapObject()   const;   // defined in EggHeapObject.h

    // ---- convenience -----------------------------------------------
    std::string printString() const;

    // ---- comparison -------------------------------------------------
    bool operator==(const EggObject& o) const { return oop_ == o.oop_; }
    bool operator!=(const EggObject& o) const { return oop_ != o.oop_; }

protected:
    uint64_t oop_{0};
    smalldbg::Debugger* debugger_{nullptr};
    uint64_t behaviorAddressSpace_{0};
};

// ---------------------------------------------------------------------------
// EggSmallInteger — immediate integer encoded in the oop itself.
// ---------------------------------------------------------------------------
class EggSmallInteger : public EggObject {
public:
    EggSmallInteger() = default;
    EggSmallInteger(uint64_t oop, smalldbg::Debugger* dbg, uint64_t bas)
        : EggObject(oop, dbg, bas) {}

    int64_t value() const { return static_cast<int64_t>(oop_) >> 1; }

    static uint64_t encode(int64_t v) {
        return (static_cast<uint64_t>(v) << 1) | EggObjectFormat::SMI_TAG;
    }
};

// ---------------------------------------------------------------------------
// Inline down-cast for SmallInteger (EggHeapObject one lives in EggHeapObject.h)
// ---------------------------------------------------------------------------
inline EggSmallInteger EggObject::asSmallInteger() const {
    return EggSmallInteger(oop_, debugger_, behaviorAddressSpace_);
}

} // namespace egg
