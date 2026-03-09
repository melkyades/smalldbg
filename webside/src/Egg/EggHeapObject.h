#pragma once

#include "EggObject.h"
#include <string>
#include <vector>
#include <cstdint>

namespace egg {

// ---------------------------------------------------------------------------
// EggHeapObject — handle to a real heap-resident Egg object.
//
// Knows its address and holds a pointer to the debugger so it can read
// header fields and slots lazily from the target process memory.
// Inherits the oop / debugger / tag-test surface from EggObject.
// ---------------------------------------------------------------------------
class EggHeapObject : public EggObject {
public:
    EggHeapObject() = default;
    EggHeapObject(uint64_t addr, smalldbg::Debugger* dbg, uint64_t bas);

    // ---- identity ---------------------------------------------------
    uint64_t address() const { return oop_; }

    // ---- header accessors ------------------------------------------
    uint16_t hash() const;
    uint8_t  flags() const;
    uint8_t  smallSize() const;
    uint32_t size() const;          // handles small vs large header
    uint32_t behaviorBits() const;  // compressed 32-bit behavior
    EggHeapObject behavior() const; // decompressed full pointer

    // ---- flag helpers -----------------------------------------------
    bool isSmallHeader() const { return (flags() & EggObjectFormat::FLAG_IS_SMALL) != 0; }
    bool isBytes()       const { return (flags() & EggObjectFormat::FLAG_IS_BYTES) != 0; }
    bool isArrayed()     const { return (flags() & EggObjectFormat::FLAG_IS_ARRAYED) != 0; }
    bool isNamed()       const { return (flags() & EggObjectFormat::FLAG_IS_NAMED) != 0; }

    // ---- slot accessors --------------------------------------------
    uint64_t      rawSlotAt(int index) const;
    EggObject     objectSlotAt(int index) const;
    EggHeapObject slotAt(int index) const;

    // ---- byte access (for String / ByteArray-like objects) ----------
    std::string bytesAsString() const;

    // ---- behavior chain / class resolution -------------------------
    /// Walk the behavior chain and return the class pointer.
    /// Behavior slot 0 = class.
    EggHeapObject classFromBehavior() const;

    /// Get the class name from an object (walks behavior → class → name slot).
    std::string className() const;

    // ---- convenience -----------------------------------------------
    std::string printString() const;
    bool isNil(uint64_t nilAddr) const { return oop_ == nilAddr; }

    /// Wrap in a typed EggKnownObject subclass.
    template<typename T>
    T as() const { return T(*this); }

private:
    uint64_t readU64(uint64_t address) const;
    uint32_t readU32(uint64_t address) const;
    uint16_t readU16(uint64_t address) const;
    uint8_t  readU8(uint64_t address) const;
    bool     readBytes(uint64_t address, void* buf, size_t len) const;
};

// ---------------------------------------------------------------------------
// Complete the inline down-cast declared in EggObject.h
// ---------------------------------------------------------------------------
inline EggHeapObject EggObject::asHeapObject() const {
    return EggHeapObject(oop_, debugger_, behaviorAddressSpace_);
}

} // namespace egg
