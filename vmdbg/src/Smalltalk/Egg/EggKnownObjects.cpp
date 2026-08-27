#include "EggKnownObjects.h"
#include <sstream>

namespace egg {

// ============================================================================
// EggBehavior
// ============================================================================

EggHeapObject EggBehavior::classRef() const         { return heap.slotAt(Slot::CLASS); }
EggHeapObject EggBehavior::methodDictionary() const { return heap.slotAt(Slot::METHODS); }
EggHeapObject EggBehavior::next() const             { return heap.slotAt(Slot::NEXT); }

// ============================================================================
// EggSpecies
// ============================================================================

EggHeapObject EggSpecies::superclass() const         { return heap.slotAt(Slot::SUPERCLASS); }
EggHeapObject EggSpecies::instanceBehavior() const   { return heap.slotAt(Slot::INSTANCE_BEHAVIOR); }
EggHeapObject EggSpecies::subclassesSlot() const     { return heap.slotAt(Slot::SUBCLASSES); }
EggHeapObject EggSpecies::instanceVariablesSlot() const { return heap.slotAt(Slot::INSTANCE_VARIABLES); }
EggHeapObject EggSpecies::moduleSlot() const         { return heap.slotAt(Slot::MODULE); }

std::string EggSpecies::name() const {
    auto nameObj = heap.slotAt(Slot::NAME);
    if (!nameObj) return {};
    return nameObj.bytesAsString();
}

std::string EggSpecies::superclassName() const {
    auto super = superclass();
    if (!super || !super.isNamed()) return {};
    return EggSpecies(super).name();
}

std::vector<std::string> EggSpecies::instanceVariableNames() const {
    auto ivarsObj = instanceVariablesSlot();
    if (!ivarsObj) return {};
    std::string ivarsStr = ivarsObj.bytesAsString();
    if (ivarsStr.empty()) return {};
    std::vector<std::string> result;
    std::istringstream iss(ivarsStr);
    std::string n;
    while (iss >> n)
        result.push_back(n);
    return result;
}

std::string EggSpecies::moduleName() const {
    auto mod = moduleSlot();
    if (!mod || !mod.isNamed()) return {};
    return mod.as<EggModule>().name();
}

// ============================================================================
// EggCompiledMethod
// ============================================================================

EggObject EggCompiledMethod::formatSlot() const {
    return heap.objectSlotAt(Slot::FORMAT);
}

EggHeapObject EggCompiledMethod::classBinding() const {
    return heap.slotAt(Slot::CLASS_BINDING);
}

std::string EggCompiledMethod::selector() const {
    auto sel = heap.objectSlotAt(Slot::SELECTOR);
    if (!sel.isHeapObject()) return {};
    return sel.asHeapObject().bytesAsString();
}

std::string EggCompiledMethod::sourceCode() const {
    auto src = heap.objectSlotAt(Slot::SOURCE_CODE);
    if (!src.isHeapObject()) return {};
    return src.asHeapObject().bytesAsString();
}

int EggCompiledMethod::argCount() const {
    EggObject fmt = formatSlot();
    if (!fmt.isSmallInteger()) return -1;
    int64_t format = fmt.asSmallInteger().value();
    return static_cast<int>(format & ARG_COUNT_MASK);
}

int EggCompiledMethod::tempCount() const {
    EggObject fmt = formatSlot();
    if (!fmt.isSmallInteger()) return -1;
    int64_t format = fmt.asSmallInteger().value();
    return static_cast<int>((format & TEMP_COUNT_MASK) >> TEMP_COUNT_SHIFT);
}

int EggCompiledMethod::environmentSize() const {
    EggObject fmt = formatSlot();
    if (!fmt.isSmallInteger()) return -1;
    int64_t format = fmt.asSmallInteger().value();
    return static_cast<int>((format >> ENV_SIZE_SHIFT) & ENV_SIZE_MASK);
}

// ============================================================================
// EggMethodDictionary
// ============================================================================

int EggMethodDictionary::tally() const {
    EggObject raw = heap.objectSlotAt(Slot::TALLY);
    if (!raw.isSmallInteger()) return 0;
    return static_cast<int>(raw.asSmallInteger().value());
}

EggHeapObject EggMethodDictionary::table() const {
    return heap.slotAt(Slot::TABLE);
}

std::vector<std::pair<std::string, EggCompiledMethod>>
EggMethodDictionary::entries() const {
    std::vector<std::pair<std::string, EggCompiledMethod>> result;
    auto tbl = table();
    if (!tbl)
        return result;

    uint32_t sz = tbl.size();

    // InlinedHashTable layout:
    //   slot 0        = named instance variable (back-pointer to MethodDictionary)
    //   slots 1..size = 128 (selector, method) pairs
    // The size in the header includes the named var, so indexed count = size - 1.
    static constexpr int NAMED_VARS = 1;  // InlinedHashTable has 1 named var
    for (uint32_t i = 0; i + 1 < sz - NAMED_VARS; i += 2) {
        auto selObj = tbl.objectSlotAt(NAMED_VARS + i);
        if (!selObj.isHeapObject()) continue;

        std::string sel = selObj.asHeapObject().bytesAsString();
        if (sel.empty()) continue;

        auto methodHeap = tbl.slotAt(NAMED_VARS + i + 1);
        if (!methodHeap) continue;
        result.push_back({sel, methodHeap.as<EggCompiledMethod>()});
    }
    return result;
}

// ============================================================================
// EggModule
// ============================================================================

std::string EggModule::name() const {
    auto nameObj = heap.slotAt(Slot::NAME);
    if (!nameObj) return {};
    return nameObj.bytesAsString();
}

// ============================================================================
// EggProcess
// ============================================================================

EggHeapObject EggProcess::nativeStack() const { return heap.slotAt(Slot::NATIVE_STACK); }
EggHeapObject EggProcess::topContext() const  { return heap.slotAt(Slot::TOP_CONTEXT); }

// ============================================================================
// EggProcessVMStack
// ============================================================================

EggHeapObject EggProcessVMStack::process() const { return heap.slotAt(Slot::PROCESS); }

int64_t EggProcessVMStack::sp() const {
    EggObject raw = heap.objectSlotAt(Slot::SP);
    if (!raw.isSmallInteger()) return 0;
    return raw.asSmallInteger().value();
}

int64_t EggProcessVMStack::bp() const {
    EggObject raw = heap.objectSlotAt(Slot::BP);
    if (!raw.isSmallInteger()) return 0;
    return raw.asSmallInteger().value();
}

} // namespace egg
