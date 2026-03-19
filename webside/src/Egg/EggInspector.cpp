#include "EggInspector.h"
#include <iostream>
#include <functional>

namespace egg {

// Pointer size for ARM64
static constexpr int PTR_SIZE = 8;

// ---- C++ struct offsets for remote memory traversal ----
// These match the field order in the Egg VM's C++ classes.
// Runtime (no vtable):
//   offset 0:  Bootstrapper*
//   offset 8:  ImageSegment*
//   offset 16: Evaluator*
static constexpr int RUNTIME_EVALUATOR_OFFSET = 16;

// Evaluator : public SExpressionVisitor (has vtable)
//   offset 0:  vtable ptr
//   offset 8:  Runtime*
//   offset 16: EvaluationContext*
static constexpr int EVALUATOR_CONTEXT_OFFSET = 16;

// EvaluationContext (no vtable):
//   offset 0:  HeapObject* _regM   (compiled code)
//   offset 8:  HeapObject* _regE   (environment)
//   offset 16: uintptr_t   _regSP
//   offset 24: uintptr_t   _regBP
//   offset 32: uintptr_t   _regPC
//   offset 40: Object*     _regS   (receiver / self)
//   offset 48: Object**    _stack
//   offset 56: Runtime*    _runtime
static constexpr int EVALCTX_REGSP_OFFSET = 16;
static constexpr int EVALCTX_REGBP_OFFSET = 24;
static constexpr int EVALCTX_STACK_OFFSET = 48;

// Evaluator frame constants (from EvaluationContext.h)
static constexpr int FRAME_TO_RECEIVER_DELTA = 1;
static constexpr int FRAME_TO_CODE_DELTA = 2;
static constexpr int FRAME_TO_FIRST_ARG_DELTA = 2;
static constexpr int FRAME_TO_FIRST_TEMP_DELTA = 5;

// ---- tag checking for raw address scanning ----

static bool isTaggedSmallInt(uint64_t ptr) {
    return (ptr & 1) != 0;
}

// ---- Construction ----

EggInspector::EggInspector(smalldbg::Debugger* dbg)
    : debugger(dbg) {}

// ---- Factory ----

EggHeapObject EggInspector::heapObjectAt(uint64_t addr) const {
    if (addr == 0 || addr == nilAddr || isTaggedSmallInt(addr))
        return EggHeapObject();
    return EggHeapObject(addr, debugger, behaviorAddressSpace);
}

EggObject EggInspector::objectAt(uint64_t addr) const {
    return EggObject(addr, debugger, behaviorAddressSpace);
}

// ---- Remote-memory helpers ----

bool EggInspector::readPtr(uint64_t addr, uint64_t& out) const {
    out = 0;
    return debugger->readMemory(addr, &out, PTR_SIZE) == smalldbg::Status::Ok;
}

bool EggInspector::readU32(uint64_t addr, uint32_t& out) const {
    out = 0;
    return debugger->readMemory(addr, &out, 4) == smalldbg::Status::Ok;
}

bool EggInspector::readU8(uint64_t addr, uint8_t& out) const {
    out = 0;
    return debugger->readMemory(addr, &out, 1) == smalldbg::Status::Ok;
}

// ---- Runtime location ----

bool EggInspector::locateRuntime() {
    auto* syms = debugger->getSymbolProvider();
    if (!syms) {
        std::cerr << "[egg] locateRuntime: no symbol provider" << std::endl;
        return false;
    }

    // Find the BEHAVIOR_ADDRESS_SPACE symbol
    auto basSym = syms->getSymbolByName("BEHAVIOR_ADDRESS_SPACE");
    if (basSym) {
        uint64_t basVal = 0;
        if (readPtr(basSym->address, basVal))
            behaviorAddressSpace = basVal;
        std::cerr << "[egg] behaviorAddressSpace = 0x" << std::hex
                  << behaviorAddressSpace << std::dec << std::endl;
    } else {
        std::cerr << "[egg] BEHAVIOR_ADDRESS_SPACE symbol not found" << std::endl;
    }

    // Find debugRuntime pointer
    auto rtSym = syms->getSymbolByName("debugRuntime");
    if (rtSym) {
        runtimeAddr = rtSym->address;
        readPtr(runtimeAddr, runtimeObjAddr);
        std::cerr << "[egg] debugRuntime at 0x" << std::hex << runtimeAddr
                  << " -> 0x" << runtimeObjAddr << std::dec << std::endl;
    } else {
        std::cerr << "[egg] debugRuntime symbol not found" << std::endl;
    }

    if (runtimeObjAddr == 0) return false;

    // Try to read nil from the runtime.
    auto nilSym = syms->getSymbolByName("KnownObjects::nil");
    if (nilSym) {
        readPtr(nilSym->address, nilAddr);
        std::cerr << "[egg] nil = 0x" << std::hex << nilAddr << std::dec << std::endl;
    } else {
        std::cerr << "[egg] nil symbol not found" << std::endl;
    }

    return runtimeObjAddr != 0;
}

// ---- Class discovery ----

void EggInspector::walkSubclasses(EggSpecies species) {
    std::string name = species.name();
    if (name.empty()) return;
    if (classCache.count(name)) return;

    ClassEntry entry;
    entry.name = name;
    entry.species = species;
    entry.superclassName = species.superclassName();
    classCache[name] = entry;

    auto subsObj = species.subclassesSlot();
    if (!subsObj || subsObj.isNil(nilAddr)) return;

    // Subclasses can be either:
    //  - a plain Array (IsArrayed set, IsNamed not set) — iterate directly
    //  - an OrderedCollection (IsNamed set) — read slot 0 for backing array
    auto arrayObj = subsObj;
    if (subsObj.isNamed() && !subsObj.isArrayed()) {
        arrayObj = subsObj.slotAt(0);
        if (!arrayObj) return;
    }

    uint32_t arraySize = arrayObj.size();
    for (uint32_t i = 0; i < arraySize && i < 500; i++) {
        auto subObj = arrayObj.slotAt(i);
        if (!subObj || subObj.isNil(nilAddr)) continue;
        walkSubclasses(subObj.as<EggSpecies>());
    }
}

bool EggInspector::discoverClasses() {
    classCache.clear();

    auto* syms = debugger->getSymbolProvider();
    if (!syms) return false;

    // Try to find a class via symbol table
    std::vector<std::string> classSymNames = {
        "KnownObjects::arrayClass",
        "KnownObjects::stringClass",
        "KnownObjects::metaclassClass",
    };

    uint64_t anyClassAddr = 0;
    for (const auto& symName : classSymNames) {
        auto sym = syms->getSymbolByName(symName);
        if (sym) {
            readPtr(sym->address, anyClassAddr);
            if (anyClassAddr != 0) break;
        }
    }

    if (anyClassAddr == 0) {
        std::cerr << "[egg] discoverClasses: no symbol-based class found, "
                     "scanning Runtime fields..." << std::endl;
        if (runtimeObjAddr != 0) {
            for (int offset = 0; offset < 800; offset += PTR_SIZE) {
                uint64_t ptr = 0;
                readPtr(runtimeObjAddr + offset, ptr);
                if (ptr == 0 || ptr == nilAddr || isTaggedSmallInt(ptr))
                    continue;
                auto obj = heapObjectAt(ptr);
                if (!obj.isNamed()) continue;
                std::string tryName = obj.as<EggSpecies>().name();
                if (!tryName.empty()) {
                    std::cerr << "[egg] discoverClasses: found class '"
                              << tryName << "' at Runtime+" << offset << std::endl;
                    anyClassAddr = ptr;
                    break;
                }
            }
        }
    }

    if (anyClassAddr == 0) {
        std::cerr << "[egg] discoverClasses: could not find any class" << std::endl;
        return false;
    }

    // Walk up the superclass chain to find the root
    auto rootClass = heapObjectAt(anyClassAddr).as<EggSpecies>();
    for (int depth = 0; depth < 50; depth++) {
        auto superObj = rootClass.superclass();
        if (!superObj || superObj.isNil(nilAddr)) break;
        rootClass = superObj.as<EggSpecies>();
    }

    // Walk down the subclass tree from root
    walkSubclasses(rootClass);

    return !classCache.empty();
}

const EggInspector::ClassEntry* EggInspector::findClassByName(
    const std::string& name) const {
    auto it = classCache.find(name);
    if (it == classCache.end()) return nullptr;
    return &it->second;
}

void EggInspector::collectSubclassesOf(
    const std::string& name,
    std::function<void(const std::string&)>& visitor) const {
    for (auto& [childName, entry] : classCache) {
        if (entry.superclassName == name)
            visitor(childName);
    }
}

// ---- Method dictionary reading ----

std::vector<std::pair<std::string, EggCompiledMethod>>
EggInspector::readMethodDictionary(const EggSpecies& species) const {
    auto behavior = species.instanceBehavior();
    if (!behavior || behavior.isNil(nilAddr))
        return {};

    auto md = behavior.as<EggBehavior>().methodDictionary();
    if (!md || md.isNil(nilAddr))
        return {};

    return md.as<EggMethodDictionary>().entries();
}

// ---- Evaluator stack reading ----

EggInspector::EvaluatorState EggInspector::readEvaluatorState() const {
    EvaluatorState st;
    if (runtimeObjAddr == 0) return st;

    // Follow pointer chain: Runtime -> Evaluator -> EvaluationContext
    uint64_t evaluatorAddr = 0;
    if (!readPtr(runtimeObjAddr + RUNTIME_EVALUATOR_OFFSET, evaluatorAddr) ||
        evaluatorAddr == 0)
        return st;

    uint64_t contextAddr = 0;
    if (!readPtr(evaluatorAddr + EVALUATOR_CONTEXT_OFFSET, contextAddr) ||
        contextAddr == 0)
        return st;

    // Read the EvaluationContext fields
    uint64_t regSP = 0, regBP = 0, stackPtr = 0;
    if (!readPtr(contextAddr + EVALCTX_REGBP_OFFSET, regBP)) return st;
    if (!readPtr(contextAddr + EVALCTX_REGSP_OFFSET, regSP)) return st;
    if (!readPtr(contextAddr + EVALCTX_STACK_OFFSET, stackPtr)) return st;

    if (stackPtr == 0 || regBP == 0) return st;

    st.stackBase = stackPtr;
    st.regBP = regBP;
    st.regSP = regSP;
    st.valid = true;
    return st;
}

uint64_t EggInspector::readStackSlot(const EvaluatorState& st,
                                     uint64_t index) const {
    if (!st.valid || st.stackBase == 0) return 0;
    uint64_t val = 0;
    // Stack slots are Object* (8 bytes each), 1-based
    readPtr(st.stackBase + (index - 1) * PTR_SIZE, val);
    return val;
}

std::vector<EggInspector::SmalltalkFrame>
EggInspector::walkSmalltalkFrames(const EvaluatorState& st,
                                  size_t maxFrames) const {
    std::vector<SmalltalkFrame> result;
    if (!st.valid) return result;

    uint64_t bp = st.regBP;
    int frameNum = 1;

    while (bp > 0 && result.size() < maxFrames) {
        SmalltalkFrame frame;
        frame.index = frameNum++;
        frame.bp = bp;

        // Code (compiled method): _stack[bp - FRAME_TO_CODE_DELTA - 1] (0-based)
        uint64_t codeAddr = readStackSlot(st, bp - FRAME_TO_CODE_DELTA);
        auto codeObj = heapObjectAt(codeAddr);

        // Receiver: _stack[bp - FRAME_TO_RECEIVER_DELTA - 1] (0-based)
        uint64_t recvAddr = readStackSlot(st, bp - FRAME_TO_RECEIVER_DELTA);
        frame.receiver = objectAt(recvAddr);

        if (codeObj) {
            auto cm = codeObj.as<EggCompiledMethod>();
            frame.method = cm;
            frame.selector = cm.selector();

            auto classBind = cm.classBinding();
            if (classBind) {
                auto species = classBind.as<EggSpecies>();
                frame.className = species.name();
            }

            // Blocks have no selector
            frame.isBlock = frame.selector.empty();
        }

        result.push_back(std::move(frame));

        // Follow the frame chain: previous bp is stored at _stack[bp-1]
        uint64_t prevBP = readStackSlot(st, bp);
        if (prevBP <= bp || prevBP == 0) break;
        bp = prevBP;
    }

    return result;
}

// ---- Object description ----

std::string EggInspector::describeRemoteObject(const EggObject& obj) const {
    if (!obj)
        return "badaddr (nullptr)";
    return obj.printString();
}

} // namespace egg
