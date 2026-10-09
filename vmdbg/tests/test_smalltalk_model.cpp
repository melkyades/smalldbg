#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "Smalltalk/HeapObject.h"
#include "Smalltalk/ObjectNamer.h"
#include "ToyDialect.h"

#include <smalldbg/Debugger.h>

#include <memory>
#include <string>
#include <vector>

using namespace smalltalk;
using namespace toy;

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
