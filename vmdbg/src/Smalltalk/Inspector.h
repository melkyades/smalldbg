#pragma once

#include "HeapObject.h"
#include "VMInspector.h"

#include <map>
#include <memory>
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
    std::vector<std::string> instanceVariableNames;
    std::vector<std::string> classVariableNames;
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

    // ---- built on the above ------------------------------------------------

    const std::map<std::string, ClassEntry>& classes() const { return classTable; }
    const ClassEntry* classNamed(const std::string& name) const;
    const ClassEntry* classAt(uint64_t oop) const;
    std::vector<std::string> subclassesOf(const std::string& name) const;
    std::vector<std::string> superclassesOf(const std::string& name) const;

    Inspector* smalltalkView() override { return this; }

protected:
    void clearClasses() { classTable.clear(); }
    void addClass(ClassEntry entry) { classTable[entry.name] = std::move(entry); }

private:
    std::map<std::string, ClassEntry> classTable;
};

} // namespace smalltalk
