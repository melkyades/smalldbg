#pragma once

#include "HeapObject.h"
#include "Tracer.h"
#include "VMInspector.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace smalltalk {

/** What is known about a class: enough to browse without re-reading the heap.
 **/
struct ClassEntry {
    std::string name;
    uint64_t oop{0};
    uint64_t superclass{0};          // oop, 0 at the root of the hierarchy
    std::string superclassName;      // empty at the root
    std::string category;
    std::string package;
    bool variable{false};            // its instances have indexed slots
    std::vector<std::string> instanceVariableNames;
    std::vector<std::string> classVariableNames;
};

/** A MethodEntry is what is known about a method: enough to list it without
 *  its source. **/
struct MethodEntry {
    std::string selector;
    std::string className;           // the class or metaclass defining it
    std::string category;
    uint64_t oop{0};
};

/** A Bytecode is one decoded instruction of a method. **/
struct Bytecode {
    int pc{0};                    // its first byte, counted as the VM's jumps count
    std::vector<uint8_t> bytes;   // the opcode and its operands
    std::string text;
    std::optional<int> target;    // the pc a jump goes to
};

/** A ClassVariable is a class variable's name and the oop it holds, which is
 *  empty when the VM's value was not read. **/
struct ClassVariable {
    std::string name;
    std::optional<uint64_t> value;
};

/** A RetainerStep is one object on the chain that keeps another alive. **/
struct RetainerStep {
    uint64_t oop{0};
    std::string className;
    std::string detail;      // the class's name, or the object printed
    bool isClass{false};     // a class in the class table
};

/** VM introspection shared by every Smalltalk dialect.
 *
 *  A dialect finds its own classes and says how to build an object from an
 *  oop; browsing the class table is done here. **/
class Inspector : public vmdbg::VMInspector {
public:
    // ---- what a dialect must answer ---------------------------------------

    /** The oop wrapped in this dialect's object type. **/
    virtual std::unique_ptr<Object> objectFor(uint64_t oop) const = 0;

    /** The same, when the oop is known to be a heap object. Returns null when
     *  it is not. **/
    virtual std::unique_ptr<HeapObject> heapObjectFor(uint64_t address) const = 0;

    /** Fill the class table. Costly, so it is done once per stop. **/
    virtual bool discoverClasses() = 0;

    /** Returns the methods `className` defines, where "Point class" names
     *  the metaclass. Returns none when the VM's methods cannot be read. **/
    virtual std::vector<MethodEntry> methodsOf(const std::string&) const {
        return {};
    }

    /** Returns the source of `method`, or an empty text when it cannot be
     *  found. **/
    virtual std::string sourceOf(const MethodEntry&) const { return {}; }

    /** Returns the bytecodes of `method`, decoded, or none when the dialect
     *  cannot decode them. **/
    virtual std::vector<Bytecode> bytecodesOf(const MethodEntry&) const { return {}; }

    /** Returns the class variables of `className`. The default has the names
     *  in the class table and no values. **/
    virtual std::vector<ClassVariable> classVariablesOf(
        const std::string& className) const;

    /** Returns what the object at `oop` prints as. The default asks the
     *  object. **/
    virtual std::string printed(uint64_t oop) const;

    // ---- built on the above ------------------------------------------------

    const std::map<std::string, ClassEntry>& classes() const { return classTable; }
    const ClassEntry* classNamed(const std::string& name) const;
    const ClassEntry* classAt(uint64_t oop) const;
    std::vector<std::string> subclassesOf(const std::string& name) const;
    std::vector<std::string> superclassesOf(const std::string& name) const;

    /** Returns the names of the slots an instance of `className` has,
     *  inherited ones first, as its slots are laid out. **/
    std::vector<std::string> slotNamesOf(const std::string& className) const;

    /** Returns the method `className` defines for `selector`, or nothing
     *  when it defines none. **/
    std::optional<MethodEntry> methodNamed(const std::string& className,
                                           const std::string& selector) const;

    /** Returns the chain that keeps `oop` alive, from the last class on the
     *  way down from the roots to `oop` itself. Returns an empty chain when
     *  `oop` cannot be reached or the VM cannot trace its heap. **/
    std::vector<RetainerStep> retainersOf(uint64_t oop);

    Inspector* smalltalkView() override { return this; }

protected:
    /** Returns a tracer over the VM's heap, or null when the VM has none. **/
    virtual std::unique_ptr<vmdbg::Tracer> makeTracer() { return nullptr; }

    void clearClasses() { classTable.clear(); }
    void addClass(ClassEntry entry) { classTable[entry.name] = std::move(entry); }

private:
    RetainerStep retainerStep(uint64_t oop) const;

    std::map<std::string, ClassEntry> classTable;
};

} // namespace smalltalk
