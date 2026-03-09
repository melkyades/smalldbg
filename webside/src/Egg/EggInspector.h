#pragma once

#include <smalldbg/Debugger.h>
#include "EggObject.h"
#include "EggHeapObject.h"
#include "EggKnownObjects.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace egg {

/// Egg VM object inspector — reads VM state and Smalltalk objects from a
/// debuggee process via `smalldbg::Debugger::readMemory()`.
///
/// An inspector for the Egg interpreter VM
/// (no JIT, ARM64 only, 64-bit pointers).
class EggInspector {
public:
    explicit EggInspector(smalldbg::Debugger* dbg);

    // ---- Factory: wrap a raw address as a typed object ---------------
    EggHeapObject heapObjectAt(uint64_t addr) const;
    EggObject objectAt(uint64_t addr) const;

    // ---- Runtime location -------------------------------------------

    /// Locate `debugRuntime`, `BEHAVIOR_ADDRESS_SPACE`, and `nil` in the
    /// target process symbol table.  Returns true when the runtime pointer
    /// was successfully read.
    bool locateRuntime();

    uint64_t getNilAddr() const { return nilAddr; }
    uint64_t getRuntimeObjAddr() const { return runtimeObjAddr; }
    uint64_t getBehaviorAddressSpace() const { return behaviorAddressSpace; }

    // ---- Class discovery and browsing --------------------------------

    struct ClassEntry {
        std::string name;
        EggSpecies species;
        std::string superclassName;
    };

    bool discoverClasses();
    const std::map<std::string, ClassEntry>& getClassCache() const { return classCache; }
    const ClassEntry* findClassByName(const std::string& name) const;

    // Class hierarchy traversal
    void collectSubclassesOf(
        const std::string& name,
        std::function<void(const std::string&)>& visitor) const;

    // ---- Method dictionary reading -----------------------------------
    std::vector<std::pair<std::string, EggCompiledMethod>>
        readMethodDictionary(const EggSpecies& species) const;

    // ---- Evaluator stack reading -------------------------------------

    /// Snapshot of the Egg evaluator registers.
    struct EvaluatorState {
        uint64_t stackBase{0};   // pointer to _stack array
        uint64_t regBP{0};       // frame pointer register
        uint64_t regSP{0};       // stack pointer register
        bool valid{false};
    };

    /// Read the current evaluator state from the runtime object.
    EvaluatorState readEvaluatorState() const;

    /// Read a single slot from the evaluator stack (1-based index).
    uint64_t readStackSlot(const EvaluatorState& st, uint64_t index) const;

    /// A single Smalltalk evaluation frame.
    struct SmalltalkFrame {
        int index{0};                  // 1-based frame number
        uint64_t bp{0};                // frame pointer (1-based stack index)
        EggCompiledMethod method;      // CompiledMethod (reified)
        EggObject receiver;            // receiver (self, reified)
        std::string selector;          // method selector string
        std::string className;         // class that defines the method
        bool isBlock{false};           // true if this is a block closure frame
    };

    /// Walk the evaluator frame chain and return Smalltalk frames.
    std::vector<SmalltalkFrame> walkSmalltalkFrames(
        const EvaluatorState& st, size_t maxFrames = 256) const;

    /// Describe an EggObject for display (printString).
    std::string describeRemoteObject(const EggObject& obj) const;

    // ---- Remote-memory helpers (for C++ struct traversal) ------------
    bool readPtr(uint64_t addr, uint64_t& out) const;
    bool readU32(uint64_t addr, uint32_t& out) const;
    bool readU8(uint64_t addr, uint8_t& out) const;

    // ---- Access to underlying debugger ------------------------------
    smalldbg::Debugger* getDebugger() const { return debugger; }

private:
    smalldbg::Debugger* debugger;

    // ---- Cached addresses in target process ----
    uint64_t behaviorAddressSpace{0};
    uint64_t runtimeAddr{0};       // address of debugRuntime pointer
    uint64_t runtimeObjAddr{0};    // *debugRuntime (the Runtime instance)
    uint64_t nilAddr{0};           // address of nil object

    // ---- Class cache ----
    std::map<std::string, ClassEntry> classCache;

    void walkSubclasses(EggSpecies species);
};

} // namespace egg
