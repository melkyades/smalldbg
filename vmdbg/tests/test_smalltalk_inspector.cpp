#include <doctest/doctest.h>

#include "Smalltalk/Inspector.h"

using smalltalk::ClassEntry;

namespace {

// An inspector whose class table is whatever the test adds.
class TestInspector : public smalltalk::Inspector {
public:
    StackRegion evaluatorStack() const override { return {}; }
    std::unique_ptr<smalltalk::Object> objectFor(uint64_t) const override { return nullptr; }
    std::unique_ptr<smalltalk::HeapObject> heapObjectFor(uint64_t) const override {
        return nullptr;
    }
    bool discoverClasses() override { return true; }

    void add(const std::string& name, uint64_t oop, uint64_t superclass) {
        ClassEntry entry;
        entry.name = name;
        entry.oop = oop;
        entry.superclass = superclass;
        addClass(entry);
    }
};

// Object <- Collection <- (Array, Bag); Object <- Point.
void addHierarchy(TestInspector& inspector) {
    inspector.add("Object", 0x10, 0);
    inspector.add("Collection", 0x20, 0x10);
    inspector.add("Point", 0x30, 0x10);
    inspector.add("Bag", 0x40, 0x20);
    inspector.add("Array", 0x50, 0x20);
}

} // namespace

TEST_CASE("a class is found by name or by oop") {
    TestInspector inspector;
    addHierarchy(inspector);

    REQUIRE(inspector.classNamed("Point") != nullptr);
    CHECK(inspector.classNamed("Point")->oop == 0x30u);
    CHECK(inspector.classNamed("Nothing") == nullptr);
    REQUIRE(inspector.classAt(0x20) != nullptr);
    CHECK(inspector.classAt(0x20)->name == "Collection");
    CHECK(inspector.classAt(0x99) == nullptr);
}

TEST_CASE("subclasses come sorted, superclasses nearest first") {
    TestInspector inspector;
    addHierarchy(inspector);

    CHECK(inspector.subclassesOf("Collection") == std::vector<std::string>{"Array", "Bag"});
    CHECK(inspector.subclassesOf("Array").empty());
    CHECK(inspector.superclassesOf("Array")
          == std::vector<std::string>{"Collection", "Object"});
    CHECK(inspector.superclassesOf("Object").empty());
}

TEST_CASE("a superclass chain that loops ends instead of repeating") {
    TestInspector inspector;
    inspector.add("A", 0x10, 0x20);
    inspector.add("B", 0x20, 0x10);

    CHECK(inspector.superclassesOf("A") == std::vector<std::string>{"B", "A"});
}

TEST_CASE("a Smalltalk inspector is its own Smalltalk view") {
    TestInspector inspector;
    vmdbg::VMInspector& general = inspector;
    CHECK(general.smalltalkView() == &inspector);
}
