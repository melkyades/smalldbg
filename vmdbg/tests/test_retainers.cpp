#include <doctest/doctest.h>

#include "Smalltalk/Inspector.h"
#include "ToyHeap.h"

#include <map>
#include <memory>
#include <string>

using smalltalk::ClassEntry;
using smalltalk::RetainerStep;

namespace {

// An object that is only a class name and a print string.
class NamedObject : public smalltalk::Object {
public:
    NamedObject(uint64_t oop, std::string className, std::string printed)
        : Object(oop, nullptr), name(std::move(className)),
          printed(std::move(printed)) {}
    size_t slotSize() const override { return 8; }
    bool isSmallInteger() const override { return false; }
    int64_t smallIntegerValue() const override { return 0; }
    std::string className() const override { return name; }
    std::string printString() const override { return printed; }

private:
    std::string name;
    std::string printed;
};

constexpr uint64_t kRoot = 0x10000;
constexpr uint64_t kHolderClass = 0x10100;
constexpr uint64_t kCache = 0x10200;
constexpr uint64_t kLeaked = 0x10300;
constexpr uint64_t kOtherClass = 0x10400;

// The roots hold a class Holder, whose cache holds the leaked object. Another
// class higher up the chain makes the cut point matter.
class HeapInspector : public smalltalk::Inspector {
public:
    HeapInspector() {
        addClass(entry("Other", kOtherClass));
        addClass(entry("Holder", kHolderClass));
    }

    StackRegion evaluatorStack() const override { return {}; }
    std::unique_ptr<smalltalk::Object> objectFor(uint64_t oop) const override {
        static const std::map<uint64_t, std::pair<std::string, std::string>> known{
            {kRoot, {"Array", "an Array"}},
            {kOtherClass, {"Other class", "Other"}},
            {kHolderClass, {"Holder class", "Holder"}},
            {kCache, {"Dictionary", "a Dictionary"}},
            {kLeaked, {"Widget", "a Widget"}},
        };
        auto found = known.find(oop);
        if (found == known.end()) return nullptr;
        return std::make_unique<NamedObject>(oop, found->second.first,
                                             found->second.second);
    }
    std::unique_ptr<smalltalk::HeapObject> heapObjectFor(uint64_t) const override {
        return nullptr;
    }
    bool discoverClasses() override { return true; }

    bool traces{true};

protected:
    std::unique_ptr<vmdbg::Tracer> makeTracer() override {
        if (!traces) return nullptr;
        auto heap = std::make_unique<ToyHeap>();
        heap->space("old", kRoot, 0x1000);
        heap->object(kRoot, {kOtherClass});
        heap->object(kOtherClass, {kHolderClass});
        heap->object(kHolderClass, {kCache});
        heap->object(kCache, {kLeaked});
        heap->object(kLeaked, {});
        heap->roots = {kRoot};
        return heap;
    }

private:
    static ClassEntry entry(const std::string& name, uint64_t oop) {
        ClassEntry entry;
        entry.name = name;
        entry.oop = oop;
        return entry;
    }
};

} // namespace

TEST_CASE("the chain that keeps an object alive starts at the last class") {
    HeapInspector inspector;
    std::vector<RetainerStep> chain = inspector.retainersOf(kLeaked);
    REQUIRE(chain.size() == 3);

    CHECK(chain[0].oop == kHolderClass);
    CHECK(chain[0].isClass);
    CHECK(chain[0].detail == "Holder");
    CHECK(chain[0].className == "Holder class");

    CHECK(chain[1].oop == kCache);
    CHECK_FALSE(chain[1].isClass);
    CHECK(chain[1].detail == "a Dictionary");

    CHECK(chain[2].oop == kLeaked);
    CHECK(chain[2].className == "Widget");
}

TEST_CASE("an object nothing holds, or a VM that cannot trace, has no chain") {
    HeapInspector inspector;
    CHECK(inspector.retainersOf(0x10800).empty());

    inspector.traces = false;
    CHECK(inspector.retainersOf(kLeaked).empty());
}
