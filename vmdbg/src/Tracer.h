#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

namespace vmdbg {

/** A Tracer finds which objects of a VM's heap can still be reached from its
 *  roots, the way a garbage collector does. An object that cannot be reached
 *  is dead: it stays in the heap only until the next collection, and its slots
 *  may point at memory that was freed and reused.
 *
 *  The tracer reads each space once into a copy and walks that copy, because
 *  reading a word at a time through the debugger costs a round trip per word.
 *  It keeps its marks in a bit per word of its own, because a debugger cannot
 *  write to the target's heap. Each VM subclasses it to say where its spaces
 *  and roots are and what each object refers to. **/
class Tracer {
public:
    struct Space {
        std::string name;
        uint64_t base{0};
        uint64_t end{0};   // exclusive
    };

    virtual ~Tracer() = default;

    /** Marks every object reachable from the roots. With `recordPaths`, it
     *  also remembers which object each one was reached from, which costs a
     *  word per object. Returns false when there is no space to walk. **/
    bool trace(bool recordPaths = false);

    /** Returns the chain of objects from a root down to `oop`, root first, or
     *  an empty chain when `oop` was not reached or paths were not recorded.
     **/
    std::vector<uint64_t> pathTo(uint64_t oop) const;

    bool isReachable(uint64_t oop) const;
    size_t reached() const { return reachedCount; }
    /** Returns how many objects the walk reached in each space. **/
    std::vector<std::pair<std::string, size_t>> perSpace() const;

protected:
    /** Returns the spaces objects live in. Nothing outside them is followed.
     **/
    virtual std::vector<Space> spaces() const = 0;
    /** Reads a span of the target into `out`, once per space before the walk.
     *  Returns false when it cannot be read. **/
    virtual bool readSpan(uint64_t base, uint64_t end,
                          std::vector<uint8_t>& out) const = 0;
    /** Calls `visit` with each root. **/
    virtual void rootsInto(
        const std::function<void(uint64_t)>& visit) const = 0;
    /** Calls `visit` with each object `oop` refers to, reading through wordAt
     *  and byteAt rather than through the debugger. **/
    virtual void slotsOf(uint64_t oop,
                         const std::function<void(uint64_t)>& visit) const = 0;
    /** Returns true for a word that could refer to an object: not zero, not a
     *  tagged integer, and aligned to the word size. **/
    virtual bool isObjectReference(uint64_t word) const;

    /** Returns true when an object really begins at `oop`. A stack is scanned
     *  conservatively, and most of its words only look like references, so a
     *  VM checks the header here. **/
    virtual bool isObjectStart(uint64_t /*oop*/) const { return true; }

    /** Returns the size of a slot, which is the VM's pointer width. **/
    virtual unsigned wordSize() const { return 8; }

    // ---- reading the copy -------------------------------------------------

    /** Reads a word of wordSize() bytes. Returns false when no space holds
     *  `address`. **/
    bool wordAt(uint64_t address, uint64_t& out) const;
    /** Reads a byte. Returns false when no space holds `address`. **/
    bool byteAt(uint64_t address, uint8_t& out) const;
    bool inSomeSpace(uint64_t address) const {
        return spaceIndexOf(address) >= 0;
    }

    /** Calls `visit` with every word of `buffer`, such as a stack the VM read.
     *  A stack mixes return addresses, saved registers and references with
     *  nothing to tell them apart, so every word is offered: that can only
     *  count too much as live, never too little. **/
    void scanConservatively(const std::vector<uint8_t>& buffer,
                            const std::function<void(uint64_t)>& visit) const;

private:
    struct Region {
        std::string name;
        uint64_t base{0};
        uint64_t end{0};
        std::vector<uint8_t> bytes;   // the copy
        std::vector<uint64_t> marks;  // a bit per word
        size_t marked{0};
    };

    /** Returns the word of wordSize() bytes at `at`. **/
    uint64_t wordFrom(const uint8_t* at) const;

    /** Returns the index of the region holding `address`, or -1. **/
    int spaceIndexOf(uint64_t address) const;
    /** Returns the same index by a binary search over the sorted regions.
     **/
    int searchSpaceIndex(uint64_t address) const;

    /** A cache from page to region, in front of the binary search: the walk
     *  looks up many addresses on the same page in a row. An entry holds the
     *  page number and the region index plus one, so zero means empty;
     *  `ambiguousPage` marks a page that more than one region touches, which
     *  is searched every time. **/
    static constexpr size_t tlbSlots = 1 << 14;
    static constexpr uint64_t pageShift = 12;
    static constexpr uint64_t indexBits = 12;
    static constexpr uint64_t indexMask = (uint64_t(1) << indexBits) - 1;
    static constexpr uint64_t ambiguousPage = indexMask;

    // For each object reached, the object it was reached from; none for a
    // root.
    std::unordered_map<uint64_t, uint64_t> arrivedFrom;

    std::vector<Region> regions;   // sorted by base
    mutable std::vector<uint64_t> tlb;
    size_t reachedCount{0};
    bool pathsRecorded{false};
};

} // namespace vmdbg
