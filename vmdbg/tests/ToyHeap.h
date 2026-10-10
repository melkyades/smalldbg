#pragma once

#include "Tracer.h"

#include <iterator>
#include <map>
#include <string>
#include <vector>

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
