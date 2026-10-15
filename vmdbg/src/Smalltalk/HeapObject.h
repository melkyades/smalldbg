#pragma once

#include "Object.h"

#include <memory>
#include <string>
#include <vector>

namespace smalltalk {

/** An object living in the heap, as opposed to a value encoded in an oop.
 *
 *  A dialect answers where its header keeps the size and the class, and what a
 *  slot is; reading slots, reading bytes, walking the superclass chain and
 *  rendering the object are done here, once. **/
class HeapObject : public Object {
public:
    HeapObject() = default;
    HeapObject(uint64_t address, smalldbg::Debugger* debugger) : Object(address, debugger) {}

    uint64_t address() const { return rawOop; }

    // ---- header: what a dialect must answer -------------------------------

    /** Slots for a pointer object, bytes for a byte object. **/
    virtual uint32_t size() const = 0;

    /** Byte objects hold characters or raw data, not oops. **/
    virtual bool isBytes() const = 0;

    /** Where the object's first slot begins. Dialects that put the header
     *  before the oop -- most of them -- leave this at the oop itself. **/
    virtual uint64_t bodyAddress() const { return rawOop; }

    /** Where slot `index` is in memory. **/
    uint64_t slotAddress(int index) const {
        return bodyAddress() + static_cast<uint64_t>(index) * slotSize();
    }

    /** The class of the receiver, however this dialect records it: a behavior
     *  pointer, a method-dictionary chain, a class-index table. **/
    virtual std::unique_ptr<HeapObject> classObject() const = 0;

    /** The name of the receiver's class. Reading it means knowing which slot of
     *  a class holds its name, which no two dialects agree on. **/
    std::string className() const override;

    /** The receiver read as a class: its name, or empty when it is not one. **/
    virtual std::string classNameIfClass() const = 0;

    /** The receiver's superclass, for kind tests. An invalid object ends the
     *  chain. **/
    virtual std::unique_ptr<HeapObject> superclassObject() const = 0;

    // ---- built on the above ------------------------------------------------

    /** The raw contents of slot `index`, unwrapped. Returns zero when it cannot
     *  be read. **/
    virtual uint64_t rawSlotAt(int index) const;

    /** Slot `index` as an object of this dialect. Heap-allocated because the
     *  concrete type belongs to the dialect and shared code holds only the
     *  base. **/
    virtual std::unique_ptr<Object> slotObjectAt(int index) const = 0;

    /** The bytes of a byte object. Returns none when they cannot be read. **/
    std::vector<uint8_t> bytes(int from = 0, int count = -1) const;

    /** Returns the text a byte object holds. A dialect whose strings keep
     *  more than their characters overrides it to leave the rest out. **/
    virtual std::string bytesAsString() const;

    /** Whether the receiver's class is `className`, or inherits from it. **/
    bool isKindOf(const std::string& className, int maxDepth = 64) const;

    void toStream(std::ostream& os, int nested = 0) const override;

protected:
    /** First refusal on rendering. A dialect answers here for the classes whose
     *  printed form it alone can build -- a method's selector, a block's home
     *  -- and leaves the rest to the shared rendering. **/
    virtual bool renderSpecial(std::ostream& /*os*/,
                               const std::string& /*className*/,
                               int /*nested*/) const { return false; }

private:
    void renderBytes(std::ostream& os, const std::string& className) const;
    void renderSlots(std::ostream& os, const std::string& className,
                     int nested) const;
};

} // namespace smalltalk
