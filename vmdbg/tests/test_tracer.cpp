#include <doctest/doctest.h>

#include "ToyHeap.h"

#include <map>

TEST_CASE("the tracer reaches what the roots refer to, and nothing else") {
    ToyHeap heap;
    heap.space("old", 0x10000, 0x1000);
    heap.object(0x10000, {0x10100, 0x10200});
    heap.object(0x10100, {0x10000});              // back to the root: a cycle
    heap.object(0x10200, {});
    // Nothing refers to this one, though it refers to a live object.
    heap.object(0x10300, {0x10200});
    heap.roots = {0x10000};

    REQUIRE(heap.trace());
    CHECK(heap.reached() == 3);
    CHECK(heap.isReachable(0x10000));
    CHECK(heap.isReachable(0x10100));
    CHECK(heap.isReachable(0x10200));
    CHECK_FALSE(heap.isReachable(0x10300));
    CHECK_FALSE(heap.isReachable(0x20000));
}

TEST_CASE("the tracer skips words that cannot refer to an object") {
    ToyHeap heap;
    heap.space("old", 0x10000, 0x1000);
    heap.object(0x10000, {0, 0x10101, 0x10104, 0x90000, 0x10200});
    heap.object(0x10200, {});
    heap.roots = {0x10000};

    REQUIRE(heap.trace());
    CHECK(heap.reached() == 2);
    CHECK(heap.isReachable(0x10200));
}

TEST_CASE("the path to an object starts at the root that reached it") {
    ToyHeap heap;
    heap.space("old", 0x10000, 0x1000);
    heap.object(0x10000, {0x10100});
    heap.object(0x10100, {0x10200});
    heap.object(0x10200, {});
    heap.roots = {0x10000};

    REQUIRE(heap.trace());
    CHECK(heap.pathTo(0x10200).empty());

    REQUIRE(heap.trace(true));
    CHECK(heap.pathTo(0x10200) ==
          std::vector<uint64_t>{0x10000, 0x10100, 0x10200});
    CHECK(heap.pathTo(0x10000) == std::vector<uint64_t>{0x10000});
    CHECK(heap.pathTo(0x10300).empty());
}

TEST_CASE("a stack scan offers every word, and the VM keeps the real objects") {
    ToyHeap heap;
    heap.space("old", 0x10000, 0x1000);
    heap.object(0x10000, {});
    heap.object(0x10100, {});
    heap.pushOnStack(0x10000);
    heap.pushOnStack(0x10108);                    // inside an object
    heap.pushOnStack(0x7ff012345678);             // a return address

    REQUIRE(heap.trace());
    CHECK(heap.reached() == 2);

    heap.checkStarts = true;
    REQUIRE(heap.trace());
    CHECK(heap.reached() == 1);
    CHECK(heap.isReachable(0x10000));
    CHECK_FALSE(heap.isReachable(0x10108));
}

TEST_CASE("the tracer counts what it reached in each space") {
    ToyHeap heap;
    heap.space("young", 0x20000, 0x100);
    heap.space("old", 0x10000, 0x1000);
    heap.object(0x20000, {0x10000, 0x10010});
    heap.object(0x10000, {});
    heap.object(0x10010, {});
    heap.roots = {0x20000};

    REQUIRE(heap.trace());
    auto counts = heap.perSpace();
    REQUIRE(counts.size() == 2);
    CHECK(counts[0] == std::make_pair(std::string("old"), size_t(2)));
    CHECK(counts[1] == std::make_pair(std::string("young"), size_t(1)));
}

TEST_CASE("the tracer reads slots of four bytes on a 32-bit VM") {
    ToyHeap heap(4);
    heap.space("old", 0x10000, 0x100);
    heap.object(0x10000, {0x10010, 0x10020});
    heap.object(0x10010, {});
    heap.object(0x10020, {});
    heap.roots = {0x10000};

    REQUIRE(heap.trace());
    CHECK(heap.reached() == 3);
    CHECK(heap.isReachable(0x10020));
}

TEST_CASE("the tracer reports when there is no space to walk") {
    ToyHeap heap;
    heap.roots = {0x10000};
    CHECK_FALSE(heap.trace());
}
