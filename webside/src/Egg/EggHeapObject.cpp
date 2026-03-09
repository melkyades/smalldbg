#include "EggHeapObject.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace egg {

// ---- construction ---------------------------------------------------

EggHeapObject::EggHeapObject(uint64_t addr, smalldbg::Debugger* dbg, uint64_t bas)
    : EggObject(addr, dbg, bas) {}

// ---- low-level memory reads ----------------------------------------

uint64_t EggHeapObject::readU64(uint64_t address) const {
    uint64_t value = 0;
    if (debugger_->readMemory(address, &value, sizeof(value)) != smalldbg::Status::Ok)
        return 0;
    return value;
}

uint32_t EggHeapObject::readU32(uint64_t address) const {
    uint32_t value = 0;
    if (debugger_->readMemory(address, &value, sizeof(value)) != smalldbg::Status::Ok)
        return 0;
    return value;
}

uint16_t EggHeapObject::readU16(uint64_t address) const {
    uint16_t value = 0;
    if (debugger_->readMemory(address, &value, sizeof(value)) != smalldbg::Status::Ok)
        return 0;
    return value;
}

uint8_t EggHeapObject::readU8(uint64_t address) const {
    uint8_t value = 0;
    if (debugger_->readMemory(address, &value, sizeof(value)) != smalldbg::Status::Ok)
        return 0;
    return value;
}

bool EggHeapObject::readBytes(uint64_t address, void* buf, size_t len) const {
    return debugger_->readMemory(address, buf, len) == smalldbg::Status::Ok;
}

// ---- header accessors -----------------------------------------------

uint16_t EggHeapObject::hash() const {
    if (!isValid()) return 0;
    return readU16(oop_ + EggObjectFormat::HASH_OFFSET);
}

uint8_t EggHeapObject::flags() const {
    if (!isValid()) return 0;
    return readU8(oop_ + EggObjectFormat::FLAGS_OFFSET);
}

uint8_t EggHeapObject::smallSize() const {
    if (!isValid()) return 0;
    return readU8(oop_ + EggObjectFormat::SIZE_OFFSET);
}

uint32_t EggHeapObject::size() const {
    if (!isValid()) return 0;
    if (isSmallHeader())
        return smallSize();
    return readU32(oop_ + EggObjectFormat::LARGE_SIZE_OFFSET);
}

uint32_t EggHeapObject::behaviorBits() const {
    if (!isValid()) return 0;
    return readU32(oop_ + EggObjectFormat::BEHAVIOR_OFFSET);
}

EggHeapObject EggHeapObject::behavior() const {
    uint32_t beh32 = behaviorBits();
    uint64_t behAddr = static_cast<uint64_t>(beh32) | behaviorAddressSpace_;
    return EggHeapObject(behAddr, debugger_, behaviorAddressSpace_);
}

// ---- slot accessors -------------------------------------------------

uint64_t EggHeapObject::rawSlotAt(int index) const {
    if (!isValid()) return 0;
    return readU64(oop_ + static_cast<uint64_t>(index) * EggObjectFormat::SLOT_SIZE);
}

EggObject EggHeapObject::objectSlotAt(int index) const {
    uint64_t raw = rawSlotAt(index);
    return EggObject(raw, debugger_, behaviorAddressSpace_);
}

EggHeapObject EggHeapObject::slotAt(int index) const {
    uint64_t raw = rawSlotAt(index);
    if (raw == 0 || (raw & EggObjectFormat::SMI_TAG) != 0)
        return EggHeapObject();  // invalid / immediate
    return EggHeapObject(raw, debugger_, behaviorAddressSpace_);
}

// ---- byte access ----------------------------------------------------

std::string EggHeapObject::bytesAsString() const {
    if (!isValid() || !isBytes()) return "";

    uint32_t sz = size();
    if (sz == 0 || sz > 0x100000) return "";

    // Egg strings store size including a null terminator.
    // asLocalString() reads size-1 bytes.
    uint32_t strLen = sz - 1;
    std::vector<char> buf(strLen + 1, 0);
    if (!readBytes(oop_, buf.data(), strLen))
        return "";

    return std::string(buf.data(), strLen);
}

// ---- behavior chain / class resolution -------------------------

EggHeapObject EggHeapObject::classFromBehavior() const {
    // Behavior slot 0 = class pointer.
    EggHeapObject beh = behavior();
    if (!beh) return EggHeapObject();

    // Walk the chain: some behaviors have nil in the class slot
    // and delegate via the "next" field (slot 2).
    for (int depth = 0; depth < 100; depth++) {
        EggHeapObject cls = beh.slotAt(0);  // BehaviorClass = slot 0
        if (cls) return cls;
        beh = beh.slotAt(2);               // BehaviorNext = slot 2
        if (!beh) break;
    }
    return EggHeapObject();
}

std::string EggHeapObject::className() const {
    EggHeapObject cls = classFromBehavior();
    if (!cls) return "";

    // Species slot 5 = name (a String/Symbol)
    EggHeapObject nameObj = cls.slotAt(5);
    if (!nameObj) return "";

    return nameObj.bytesAsString();
}

// ---- convenience -----------------------------------------------

std::string EggHeapObject::printString() const {
    if (!isValid()) return "<invalid>";

    std::string cls = className();

    if (isBytes()) {
        if (cls == "String" || cls == "Symbol") {
            std::string s = bytesAsString();
            if (s.size() > 50) s = s.substr(0, 50) + "...";
            if (cls == "Symbol") return "#" + s;
            return "'" + s + "'";
        }
    }

    if (!cls.empty())
        return "a " + cls;

    std::ostringstream oss;
    oss << "0x" << std::hex << oop_;
    return oss.str();
}

std::string EggObject::printString() const {
    if (isSmallInteger())
        return std::to_string(asSmallInteger().value());
    if (isHeapObject())
        return asHeapObject().printString();
    return "<invalid>";
}

} // namespace egg
