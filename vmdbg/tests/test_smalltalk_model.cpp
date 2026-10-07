#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "Smalltalk/HeapObject.h"
#include "Smalltalk/ObjectNamer.h"

#include <smalldbg/Debugger.h>

#include <memory>
#include <string>
#include <vector>

using namespace smalltalk;

namespace {

// A made-up dialect, just enough of one for the shared code to run on: 8-byte
// slots, SmallIntegers tagged in the low bit, and a header of 16 bytes before
// each object holding its class, its size and whether it holds bytes.
constexpr uint64_t kClassOffset = 16;
constexpr uint64_t kSizeOffset = 8;
constexpr uint64_t kFlagsOffset = 4;
constexpr uint32_t kBytesFlag = 1;

uint64_t smallInteger(int64_t value) { return (static_cast<uint64_t>(value) << 1) | 1; }

class TestObject : public Object {
public:
    using Object::Object;
    size_t slotSize() const override { return 8; }
    bool isSmallInteger() const override { return (rawOop & 1) != 0; }
    int64_t smallIntegerValue() const override { return static_cast<int64_t>(rawOop) >> 1; }
};

class TestHeapObject : public HeapObject {
public:
    using HeapObject::HeapObject;
    size_t slotSize() const override { return 8; }
    bool isSmallInteger() const override { return false; }
    int64_t smallIntegerValue() const override { return 0; }

    uint32_t size() const override { return static_cast<uint32_t>(word(rawOop - kSizeOffset, 4)); }
    bool isBytes() const override { return (word(rawOop - kFlagsOffset, 4) & kBytesFlag) != 0; }

    std::unique_ptr<HeapObject> classObject() const override {
        return at(word(rawOop - kClassOffset, 8));
    }
    std::unique_ptr<HeapObject> superclassObject() const override { return at(rawSlotAt(1)); }
    std::string classNameIfClass() const override {
        return TestHeapObject(rawSlotAt(0), dbg).bytesAsString();
    }

    std::unique_ptr<Object> slotObjectAt(int index) const override {
        uint64_t oop = rawSlotAt(index);
        if (oop & 1) return std::make_unique<TestObject>(oop, dbg);
        return std::make_unique<TestHeapObject>(oop, dbg);
    }

private:
    uint64_t word(uint64_t address, size_t width) const {
        uint64_t value = 0;
        dbg->readMemory(address, &value, width);
        return value;
    }

    // No class, or no superclass, is an invalid object, which ends a chain.
    std::unique_ptr<HeapObject> at(uint64_t address) const {
        if (address == 0) return std::make_unique<TestHeapObject>();
        return std::make_unique<TestHeapObject>(address, dbg);
    }
};

// Lays out objects of the made-up dialect one after another, and reads them
// back through a debugger built over the result as a snapshot.
class Heap {
public:
    static constexpr uint64_t kBase = 0x1000;

    uint64_t object(uint64_t cls, const std::vector<uint64_t>& slots) {
        uint64_t oop = allocate(cls, static_cast<uint32_t>(slots.size()), 0, slots.size() * 8);
        for (size_t i = 0; i < slots.size(); i++) put(oop + i * 8, slots[i], 8);
        return oop;
    }

    uint64_t bytes(uint64_t cls, const std::string& text) {
        uint64_t oop = allocate(cls, static_cast<uint32_t>(text.size()), kBytesFlag, text.size());
        for (size_t i = 0; i < text.size(); i++) memory[offset(oop) + i] = static_cast<uint8_t>(text[i]);
        return oop;
    }

    void setSlot(uint64_t oop, int index, uint64_t value) {
        put(oop + static_cast<uint64_t>(index) * 8, value, 8);
    }

    // A heap that grew since it was last read is opened again; objects built
    // before keep the debugger they were built with.
    smalldbg::Debugger* debugger() {
        if (opened.empty() || openedSize != memory.size()) {
            auto dbg = std::make_unique<smalldbg::Debugger>(
                smalldbg::Mode::External, nullptr, smalldbg::Debuggee::Snapshot);
            REQUIRE(dbg->openSnapshot({smalldbg::SnapshotRegion::fromBytes(kBase, memory)})
                    == smalldbg::Status::Ok);
            opened.push_back(std::move(dbg));
            openedSize = memory.size();
        }
        return opened.back().get();
    }

    TestHeapObject at(uint64_t oop) { return TestHeapObject(oop, debugger()); }

private:
    size_t offset(uint64_t address) const { return static_cast<size_t>(address - kBase); }

    void put(uint64_t address, uint64_t value, size_t width) {
        for (size_t i = 0; i < width; i++)
            memory[offset(address) + i] = static_cast<uint8_t>(value >> (8 * i));
    }

    uint64_t allocate(uint64_t cls, uint32_t size, uint32_t flags, size_t bodyBytes) {
        uint64_t oop = kBase + memory.size() + kClassOffset;
        memory.resize(memory.size() + kClassOffset + ((bodyBytes + 7) / 8) * 8);
        put(oop - kClassOffset, cls, 8);
        put(oop - kSizeOffset, size, 4);
        put(oop - kFlagsOffset, flags, 4);
        return oop;
    }

    std::vector<uint8_t> memory;
    std::vector<std::unique_ptr<smalldbg::Debugger>> opened;
    size_t openedSize{0};
};

// A heap with the classes the tests use. A class's slot 0 is its name, slot 1
// its superclass.
struct Kernel {
    Heap heap;
    uint64_t object, string, symbol, array, point;

    Kernel() {
        string = heap.object(0, {0, 0});
        heap.setSlot(string, 0, heap.bytes(string, "String"));
        object = defineClass("Object", 0);
        heap.setSlot(string, 1, object);
        symbol = defineClass("Symbol", string);
        array = defineClass("Array", object);
        point = defineClass("Point", object);
    }

    uint64_t defineClass(const std::string& name, uint64_t superclass) {
        return heap.object(0, {heap.bytes(string, name), superclass});
    }
};

} // namespace

TEST_CASE("a slot past the end of the heap reads as zero") {
    Kernel kernel;
    auto point = kernel.heap.at(kernel.heap.object(kernel.point, {smallInteger(3)}));
    CHECK(point.rawSlotAt(0) == smallInteger(3));
    CHECK(point.rawSlotAt(1) == 0u);
    CHECK(point.rawSlotAt(-1) == 0u);
}

TEST_CASE("a class name takes the article Smalltalk would print it with") {
    CHECK(withArticle("Array") == "an Array");
    CHECK(withArticle("Object") == "an Object");
    CHECK(withArticle("Point") == "a Point");
    CHECK(articleFor("") == "a");
}

TEST_CASE("an immediate prints its value") {
    Heap heap;
    TestObject number(smallInteger(-42), heap.debugger());
    CHECK(number.isImmediate());
    CHECK_FALSE(number.isHeapObject());
    CHECK(number.printString() == "-42");
}

TEST_CASE("a heap object knows its class and what it inherits from") {
    Kernel kernel;
    auto point = kernel.heap.at(
        kernel.heap.object(kernel.point, {smallInteger(3), smallInteger(4)}));

    CHECK(point.isHeapObject());
    CHECK(point.className() == "Point");
    CHECK(point.isKindOf("Point"));
    CHECK(point.isKindOf("Object"));
    CHECK_FALSE(point.isKindOf("Array"));
    CHECK(point.printString() == "a Point");
}

TEST_CASE("strings, symbols and arrays print as source would write them") {
    Kernel kernel;
    Heap& heap = kernel.heap;

    CHECK(heap.at(heap.bytes(kernel.string, "hello")).printString() == "'hello'");
    CHECK(heap.at(heap.bytes(kernel.symbol, "foo")).printString() == "#foo");

    auto array = heap.at(heap.object(kernel.array,
        {smallInteger(1), smallInteger(2), smallInteger(3)}));
    CHECK(array.printString() == "(1 2 3)");

    std::string text(40, 'x');
    CHECK(heap.at(heap.bytes(kernel.string, text)).printString()
          == "'" + std::string(32, 'x') + "...'");
}

TEST_CASE("an object whose class cannot be read prints as unknown") {
    Kernel kernel;
    auto stray = kernel.heap.at(kernel.heap.object(0, {}));
    CHECK(stray.className().empty());
    CHECK(stray.printString() == "an unknown Object");
}

TEST_CASE("a namer names the oops of its own debugger only") {
    int first = 0, second = 0;
    auto* debugger = reinterpret_cast<smalldbg::Debugger*>(&first);
    auto* other = reinterpret_cast<smalldbg::Debugger*>(&second);

    CHECK(objectName(debugger, 0x100).empty());
    setObjectNamer(debugger, [](uint64_t oop) {
        return oop == 0x100 ? std::string("the method dictionaries") : std::string();
    });
    CHECK(objectName(debugger, 0x100) == "the method dictionaries");
    CHECK(objectName(debugger, 0x200).empty());
    CHECK(objectName(other, 0x100).empty());
}
