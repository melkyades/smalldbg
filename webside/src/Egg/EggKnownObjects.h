#pragma once

#include "EggHeapObject.h"
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

namespace egg {

// ---------------------------------------------------------------------------
// EggKnownObject — base for all typed heap-object wrappers.
//
// Holds the underlying EggHeapObject and provides identity / validity.
// Subclasses add domain-specific slot accessors.
// ---------------------------------------------------------------------------
class EggKnownObject {
public:
    EggKnownObject() = default;
    explicit EggKnownObject(EggHeapObject h) : heap(h) {}

    explicit operator bool() const { return bool(heap); }
    EggHeapObject heapObject() const { return heap; }
    uint64_t oop() const { return heap.oop(); }

protected:
    EggHeapObject heap;
};

// ---------------------------------------------------------------------------
// EggBehavior — typed view of a Behavior heap object.
//
//   Slot 0: class       (Species that owns this behavior)
//   Slot 1: methods     (MethodDictionary)
//   Slot 2: next        (next Behavior in the lookup chain)
// ---------------------------------------------------------------------------
class EggBehavior : public EggKnownObject {
public:
    EggBehavior() = default;
    explicit EggBehavior(EggHeapObject obj) : EggKnownObject(obj) {}

    EggHeapObject classRef() const;
    EggHeapObject methodDictionary() const;
    EggHeapObject next() const;

    struct Slot {
        static constexpr int CLASS   = 0;
        static constexpr int METHODS = 1;
        static constexpr int NEXT    = 2;
    };
};

// ---------------------------------------------------------------------------
// EggSpecies — typed view of a Species / Class heap object.
//
//   Slot 0: superclass
//   Slot 1: instanceBehavior
//   Slot 2: format
//   Slot 3: organization
//   Slot 4: instanceVariables   (String: space-separated ivar names)
//   Slot 5: name                (String)
//   Slot 6: subclasses          (OrderedCollection)
//   Slot 7: namespaces
//   Slot 8: module              (Module)
//
//   Metaclass slot 5: class     (the instance-side class)
// ---------------------------------------------------------------------------
class EggSpecies : public EggKnownObject {
public:
    EggSpecies() = default;
    explicit EggSpecies(EggHeapObject obj) : EggKnownObject(obj) {}

    EggHeapObject superclass() const;
    EggHeapObject instanceBehavior() const;
    std::string   name() const;
    EggHeapObject subclassesSlot() const;
    EggHeapObject instanceVariablesSlot() const;
    EggHeapObject moduleSlot() const;

    // ---- Convenience accessors ----
    std::string superclassName() const;
    std::vector<std::string> instanceVariableNames() const;
    std::string moduleName() const;

    struct Slot {
        static constexpr int SUPERCLASS          = 0;
        static constexpr int INSTANCE_BEHAVIOR   = 1;
        static constexpr int FORMAT              = 2;
        static constexpr int ORGANIZATION        = 3;
        static constexpr int INSTANCE_VARIABLES  = 4;
        static constexpr int NAME                = 5;
        static constexpr int SUBCLASSES          = 6;
        static constexpr int NAMESPACES          = 7;
        static constexpr int MODULE              = 8;
        static constexpr int METACLASS_CLASS     = 5;
    };
};

// ---------------------------------------------------------------------------
// EggCompiledMethod — typed view of a CompiledMethod heap object.
//
//   Slot 0: format       (SmallInteger bitmap: argCount, tempCount, flags)
//   Slot 1: executableCode
//   Slot 2: treecodes    (SExpression tree / bytecodes)
//   Slot 3: classBinding (Species that defines this method)
//   Slot 4: selector     (Symbol)
//   Slot 5: sourceCode   (String)
//   Slot 6+: literals
// ---------------------------------------------------------------------------
class EggCompiledMethod : public EggKnownObject {
public:
    EggCompiledMethod() = default;
    explicit EggCompiledMethod(EggHeapObject obj) : EggKnownObject(obj) {}

    EggObject     formatSlot() const;
    EggHeapObject classBinding() const;
    std::string   selector() const;
    std::string   sourceCode() const;

    int argCount() const;
    int tempCount() const;
    int environmentSize() const;

    struct Slot {
        static constexpr int FORMAT        = 0;
        static constexpr int EXECUTABLE    = 1;
        static constexpr int TREECODES     = 2;
        static constexpr int CLASS_BINDING = 3;
        static constexpr int SELECTOR      = 4;
        static constexpr int SOURCE_CODE   = 5;
        static constexpr int FIRST_LITERAL = 6;
    };

    // Format bitmask constants (from MethodFlags enum)
    static constexpr int ARG_COUNT_MASK       = 0x3F;
    static constexpr int TEMP_COUNT_MASK      = 0x1FE000;
    static constexpr int TEMP_COUNT_SHIFT     = 13;
    static constexpr int ENV_SIZE_SHIFT       = 25;
    static constexpr int ENV_SIZE_MASK        = 0x3F;
    static constexpr int NEEDS_ENVIRONMENT    = 0x400000;
};

// ---------------------------------------------------------------------------
// EggMethodDictionary — typed view of a MethodDictionary.
//
//   Slot 0: tally  (SmallInteger)
//   Slot 1: table  (Array of alternating selector/method pairs)
// ---------------------------------------------------------------------------
class EggMethodDictionary : public EggKnownObject {
public:
    EggMethodDictionary() = default;
    explicit EggMethodDictionary(EggHeapObject obj) : EggKnownObject(obj) {}

    int tally() const;
    EggHeapObject table() const;

    /// Iterate table entries as (selector-string, CompiledMethod) pairs.
    std::vector<std::pair<std::string, EggCompiledMethod>> entries() const;

    struct Slot {
        static constexpr int TALLY = 0;
        static constexpr int TABLE = 1;
    };
};

// ---------------------------------------------------------------------------
// EggModule — typed view of a Module.
//
//   Slot 0: name    (String)
//   Slot 6: classes
// ---------------------------------------------------------------------------
class EggModule : public EggKnownObject {
public:
    EggModule() = default;
    explicit EggModule(EggHeapObject obj) : EggKnownObject(obj) {}

    std::string name() const;

    struct Slot {
        static constexpr int NAME    = 0;
        static constexpr int CLASSES = 6;
    };
};

// ---------------------------------------------------------------------------
// EggProcess — typed view of a Smalltalk Process.
//
//   Slot 1: nativeStack   (ProcessVMStack — the evaluator stack object)
//   Slot 2: topContext
// ---------------------------------------------------------------------------
class EggProcess : public EggKnownObject {
public:
    EggProcess() = default;
    explicit EggProcess(EggHeapObject obj) : EggKnownObject(obj) {}

    EggHeapObject nativeStack() const;
    EggHeapObject topContext() const;

    struct Slot {
        static constexpr int NATIVE_STACK = 1;
        static constexpr int TOP_CONTEXT  = 2;
    };
};

// ---------------------------------------------------------------------------
// EggProcessVMStack — typed view of a ProcessVMStack.
//
//   Slot 0: process  (Process — back-pointer)
//   Slot 1: sp       (SmallInteger — stack pointer)
//   Slot 2: bp       (SmallInteger — frame pointer)
// ---------------------------------------------------------------------------
class EggProcessVMStack : public EggKnownObject {
public:
    EggProcessVMStack() = default;
    explicit EggProcessVMStack(EggHeapObject obj) : EggKnownObject(obj) {}

    EggHeapObject process() const;
    int64_t sp() const;
    int64_t bp() const;

    struct Slot {
        static constexpr int PROCESS = 0;
        static constexpr int SP      = 1;
        static constexpr int BP      = 2;
    };
};

} // namespace egg
