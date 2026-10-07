#pragma once

#include <cstdint>
#include <ostream>
#include <string>

namespace smalldbg { class Debugger; }

namespace smalltalk {

class HeapObject;

/** An oop as every dialect has one: either an immediate value encoded in the
 *  pointer itself, or the address of an object in the heap.
 *
 *  A dialect subclasses this and answers the handful of questions its encoding
 *  decides -- which tag bits mean what, how wide a slot is. Everything built on
 *  those answers (rendering, class names, kind tests) is written once here.
 *
 *  Objects are value types: a dialect's own class derives from this and is
 *  passed and returned by value within that dialect. Shared code takes a
 *  `const Object&` so it never has to know which dialect it has. **/
class Object {
public:
    Object() = default;
    Object(uint64_t oop, smalldbg::Debugger* debugger) : rawOop(oop), dbg(debugger) {}
    virtual ~Object() = default;

    uint64_t oop() const { return rawOop; }

    /** The debugger the object's heap is read through. **/
    smalldbg::Debugger* debugger() const { return dbg; }
    bool isValid() const { return dbg != nullptr; }
    explicit operator bool() const { return isValid() && rawOop != 0; }

    // ---- encoding: what a dialect must answer -----------------------------

    /** Bytes per slot and per oop. 4 in a 32-bit VM, 8 in a 64-bit one. **/
    virtual size_t slotSize() const = 0;

    /** Returns true when the oop carries its value rather than an address. The
     *  default covers the common case of SmallInteger being the only immediate.
     **/
    virtual bool isImmediate() const { return isSmallInteger(); }

    virtual bool isSmallInteger() const = 0;
    virtual int64_t smallIntegerValue() const = 0;

    /** Dialects whose encoding has no such immediate leave these alone. **/
    virtual bool isCharacter() const { return false; }
    virtual uint32_t characterValue() const { return 0; }
    virtual bool isSmallFloat() const { return false; }
    virtual double smallFloatValue() const { return 0.0; }

    /** How an immediate prints. A dialect that adds an immediate type answers
     *  for it here. **/
    virtual std::string immediateString() const;

    // ---- built on the above ------------------------------------------------

    bool isHeapObject() const { return isValid() && rawOop != 0 && !isImmediate(); }

    /** The distinguished objects, when the dialect knows where they live. **/
    virtual bool isNil() const { return false; }
    virtual bool isTrue() const { return false; }
    virtual bool isFalse() const { return false; }

    /** A heap object that is not nil: something worth following. **/
    bool isPresent() const { return isHeapObject() && !isNil(); }

    /** The receiver's class name, or empty when it cannot be read. **/
    virtual std::string className() const { return {}; }

    /** A short human-readable rendering: the value for an immediate, "a Point"
     *  or the contents for a heap object. **/
    virtual std::string printString() const;

    /** The same, expanded `nested` levels deep into slots. **/
    virtual void toStream(std::ostream& os, int nested = 0) const;

    bool operator==(const Object& other) const { return rawOop == other.rawOop; }
    bool operator!=(const Object& other) const { return rawOop != other.rawOop; }

protected:
    uint64_t rawOop{0};
    smalldbg::Debugger* dbg{nullptr};
};

inline std::ostream& operator<<(std::ostream& os, const Object& object) {
    object.toStream(os);
    return os;
}

/** Article + class name, the way Smalltalk prints an object with no printOn:
 *  of its own. Shared so every dialect says "an Array" and "a Point" alike. **/
std::string articleFor(const std::string& className);
std::string withArticle(const std::string& className);

} // namespace smalltalk
