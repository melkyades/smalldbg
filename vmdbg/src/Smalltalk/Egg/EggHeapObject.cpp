#include "EggHeapObject.h"
#include "EggKnownObjects.h"
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

    EggHeapObject nameObj = cls.slotAt(EggSpecies::Slot::NAME);
    if (nameObj && nameObj.isBytes())
        return nameObj.bytesAsString();

    // Metaclass: slot 5 is the instance-side class, not a name string.
    // Render "InstanceClassName class" so callers can detect class objects.
    if (nameObj) {
        EggHeapObject instanceName = nameObj.slotAt(EggSpecies::Slot::NAME);
        if (instanceName && instanceName.isBytes())
            return instanceName.bytesAsString() + " class";
    }

    return "";
}

// ---- convenience -----------------------------------------------

std::string EggHeapObject::printString() const {
    if (!isValid()) return "<invalid>";

    std::string cls = className();

    if (isBytes()) {
        if (cls == "String") {
            std::string s = bytesAsString();
            if (s.size() > 50) s = s.substr(0, 50) + "...";
            return "'" + s + "'";
        }
        if (cls == "Symbol")
            return "#" + bytesAsString();
    }

    if (cls == "UndefinedObject") return "nil";
    if (cls == "True")  return "true";
    if (cls == "False") return "false";

    if (cls == "CompiledMethod" || cls == "FFIMethod") {
        EggObject selRaw = objectSlotAt(EggCompiledMethod::Slot::SELECTOR);
        std::string sel = (selRaw.isHeapObject() && selRaw.asHeapObject())
            ? selRaw.asHeapObject().bytesAsString() : "";
        EggHeapObject binding = as<EggCompiledMethod>().classBinding();
        std::string bindingStr = binding ? binding.printString() : "";
        if (sel.empty() && bindingStr.empty())
            return "<unnamed CompiledMethod>";
        return (bindingStr.empty() ? "nil" : bindingStr) + ">>#" +
               (sel.empty() ? "nil" : sel);
    }

    if (cls == "CompiledBlock") {
        EggObject fmt = objectSlotAt(0);
        int blockNum = fmt.isSmallInteger()
            ? static_cast<int>((fmt.asSmallInteger().value() & 0x3FC000) >> 14) : 0;
        EggHeapObject methodObj = slotAt(2);
        std::string methodStr = methodObj ? methodObj.printString() : "<unknown method>";
        return "block " + std::to_string(blockNum) + " of " + methodStr;
    }

    if (cls == "Behavior") {
        EggHeapObject classRef = as<EggBehavior>().classRef();
        return (classRef ? EggSpecies(classRef).name() : "") + " behavior";
    }

    if (cls == "Metaclass") {
        EggHeapObject instanceClass = slotAt(EggSpecies::Slot::METACLASS_CLASS);
        return (instanceClass ? EggSpecies(instanceClass).name() : "") + " class";
    }

    // A class object: its species is a metaclass, so className() ended in " class".
    if (cls.size() > 6 && cls.compare(cls.size() - 6, 6, " class") == 0)
        return cls.substr(0, cls.size() - 6);

    if (!cls.empty()) {
        bool startsWithVowel = cls.find_first_of("AEIOUaeiou") == 0;
        return (startsWithVowel ? "an " : "a ") + cls;
    }

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
