#include <doctest/doctest.h>

#include "Tracer.h"

#include <map>

namespace {

// A heap the test lays out by hand: each object is a run of slots, and the
// roots are listed or found on a stack.
class ToyHeap : public vmdbg::Tracer {
public:
    explicit ToyHeap(unsigned width = 8) : width(width) {}

    void space(const std::string& name, uint64_t base, size_t size) {
        spaceList.push_back({name, base, base + size});
        memory[base].assign(size, 0);
    }

    void object(uint64_t oop, std::vector<uint64_t> slots) {
        slotCounts[oop] = slots.size();
        for (size_t i = 0; i < slots.size(); i++)
            put(oop + i * width, slots[i]);
    }

    void pushOnStack(uint64_t word) {
        stack.resize(stack.size() + width);
        store(stack.data() + stack.size() - width, word);
    }

    std::vector<uint64_t> roots;
    bool checkStarts{false};

protected:
    std::vector<Space> spaces() const override { return spaceList; }

    bool readSpan(uint64_t base, uint64_t end,
                  std::vector<uint8_t>& out) const override {
        auto found = memory.find(base);
        if (found == memory.end()) return false;
        out.assign(found->second.begin(),
                   found->second.begin() + static_cast<size_t>(end - base));
        return true;
    }

    void rootsInto(const std::function<void(uint64_t)>& visit) const override {
        for (uint64_t root : roots) visit(root);
        scanConservatively(stack, visit);
    }

    void slotsOf(uint64_t oop,
                 const std::function<void(uint64_t)>& visit) const override {
        auto found = slotCounts.find(oop);
        if (found == slotCounts.end()) return;
        for (size_t i = 0; i < found->second; i++) {
            uint64_t slot = 0;
            if (wordAt(oop + i * width, slot)) visit(slot);
        }
    }

    bool isObjectStart(uint64_t oop) const override {
        return !checkStarts || slotCounts.count(oop) != 0;
    }

    unsigned wordSize() const override { return width; }

private:
    void put(uint64_t address, uint64_t word) {
        auto holder = std::prev(memory.upper_bound(address));
        store(holder->second.data() + (address - holder->first), word);
    }

    void store(uint8_t* at, uint64_t word) const {
        if (width == 4) *reinterpret_cast<uint32_t*>(at) = uint32_t(word);
        else *reinterpret_cast<uint64_t*>(at) = word;
    }

    unsigned width;
    std::vector<Space> spaceList;
    std::map<uint64_t, std::vector<uint8_t>> memory;
    std::map<uint64_t, size_t> slotCounts;
    std::vector<uint8_t> stack;
};

} // namespace

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
