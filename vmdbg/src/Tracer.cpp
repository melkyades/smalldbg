#include "Tracer.h"

#include <algorithm>

namespace vmdbg {

bool Tracer::isObjectReference(uint64_t word) const {
    if (word == 0) return false;
    if (word & 1) return false;                  // a tagged integer
    return word % wordSize() == 0;
}

uint64_t Tracer::wordFrom(const uint8_t* at) const {
    if (wordSize() == 4) return *reinterpret_cast<const uint32_t*>(at);
    return *reinterpret_cast<const uint64_t*>(at);
}

int Tracer::searchSpaceIndex(uint64_t address) const {
    // The regions do not overlap, so only the last one starting at or below
    // the address can hold it.
    size_t low = 0, high = regions.size();
    while (low < high) {
        size_t mid = (low + high) / 2;
        if (regions[mid].base <= address) low = mid + 1;
        else high = mid;
    }
    if (low == 0) return -1;
    const Region& candidate = regions[low - 1];
    if (address >= candidate.end) return -1;
    return static_cast<int>(low - 1);
}

// A page that no region starts inside belongs to at most one region, so the
// cache keeps that region for the whole page. A region may end inside the page,
// so each hit still checks the end.
int Tracer::spaceIndexOf(uint64_t address) const {
    if (tlb.empty()) return searchSpaceIndex(address);

    const uint64_t page = address >> pageShift;
    uint64_t& entry = tlb[page & (tlbSlots - 1)];
    const uint64_t slot = entry & indexMask;
    if ((entry >> indexBits) == page && slot != ambiguousPage) {
        if (slot == 0) return -1;
        const Region& region = regions[slot - 1];
        return address < region.end ? static_cast<int>(slot - 1) : -1;
    }

    const uint64_t pageStart = page << pageShift;
    const int owner = searchSpaceIndex(pageStart);
    const size_t next = static_cast<size_t>(owner + 1);
    const bool shared = next < regions.size() &&
                        regions[next].base < pageStart + (1 << pageShift);
    entry = (page << indexBits) |
            (shared ? ambiguousPage : static_cast<uint64_t>(owner + 1));
    if (shared) return searchSpaceIndex(address);
    if (owner < 0) return -1;
    const Region& region = regions[owner];
    return address < region.end ? owner : -1;
}

bool Tracer::wordAt(uint64_t address, uint64_t& out) const {
    int index = spaceIndexOf(address);
    if (index < 0) return false;
    const Region& region = regions[index];
    size_t offset = static_cast<size_t>(address - region.base);
    if (offset + wordSize() > region.bytes.size()) return false;
    out = wordFrom(region.bytes.data() + offset);
    return true;
}

bool Tracer::byteAt(uint64_t address, uint8_t& out) const {
    int index = spaceIndexOf(address);
    if (index < 0) return false;
    const Region& region = regions[index];
    size_t offset = static_cast<size_t>(address - region.base);
    if (offset >= region.bytes.size()) return false;
    out = region.bytes[offset];
    return true;
}

void Tracer::scanConservatively(
    const std::vector<uint8_t>& buffer,
    const std::function<void(uint64_t)>& visit) const {
    const unsigned step = wordSize();
    for (size_t offset = 0; offset + step <= buffer.size(); offset += step)
        visit(wordFrom(buffer.data() + offset));
}

bool Tracer::trace(bool recordPaths) {
    regions.clear();
    reachedCount = 0;
    arrivedFrom.clear();
    pathsRecorded = recordPaths;

    for (const Space& space : spaces()) {
        if (space.end <= space.base) continue;
        Region region;
        region.name = space.name;
        region.base = space.base;
        if (!readSpan(space.base, space.end, region.bytes)) continue;
        if (region.bytes.empty()) continue;
        region.end = region.base + region.bytes.size();

        size_t words = region.bytes.size() / wordSize() + 1;
        region.marks.assign(words / 64 + 1, 0);
        regions.push_back(std::move(region));
    }
    if (regions.empty()) return false;

    std::sort(regions.begin(), regions.end(),
              [](const Region& a, const Region& b) { return a.base < b.base; });

    tlb.clear();
    if (regions.size() < ambiguousPage - 1) tlb.assign(tlbSlots, 0);

    // A list of objects still to walk, rather than recursion: a chain of
    // objects can be far longer than the call stack is deep.
    std::vector<uint64_t> pending;
    pending.reserve(1 << 16);

    // The object whose slots are being walked, recorded as where each new
    // object was reached from.
    uint64_t from = 0;

    auto offer = [&](uint64_t oop) {
        if (!isObjectReference(oop)) return;
        int index = spaceIndexOf(oop);
        if (index < 0) return;
        if (!isObjectStart(oop)) return;
        Region& region = regions[index];
        size_t bit = static_cast<size_t>((oop - region.base) / wordSize());
        uint64_t& cell = region.marks[bit / 64];
        uint64_t mask = uint64_t(1) << (bit % 64);
        if (cell & mask) return;   // already marked, as in a cycle
        cell |= mask;
        region.marked++;
        reachedCount++;
        if (recordPaths && from != 0) arrivedFrom.emplace(oop, from);
        pending.push_back(oop);
    };

    rootsInto(offer);

    while (!pending.empty()) {
        uint64_t oop = pending.back();
        pending.pop_back();
        from = oop;
        slotsOf(oop, offer);
    }
    return true;
}

// Each object recorded the one it was reached from, so the path is built by
// following those links back up to a root.
std::vector<uint64_t> Tracer::pathTo(uint64_t oop) const {
    std::vector<uint64_t> path;
    if (!pathsRecorded || !isReachable(oop)) return path;

    uint64_t at = oop;
    // The links cannot form a loop, but the bound keeps a damaged heap from
    // hanging the walk.
    for (size_t step = 0; step <= reachedCount; step++) {
        path.push_back(at);
        auto found = arrivedFrom.find(at);
        if (found == arrivedFrom.end()) break;
        at = found->second;
    }
    std::reverse(path.begin(), path.end());
    return path;
}

bool Tracer::isReachable(uint64_t oop) const {
    int index = spaceIndexOf(oop);
    if (index < 0) return false;
    const Region& region = regions[index];
    size_t bit = static_cast<size_t>((oop - region.base) / wordSize());
    if (bit / 64 >= region.marks.size()) return false;
    return (region.marks[bit / 64] >> (bit % 64)) & 1;
}

std::vector<std::pair<std::string, size_t>> Tracer::perSpace() const {
    std::vector<std::pair<std::string, size_t>> out;
    out.reserve(regions.size());
    for (const Region& region : regions)
        out.emplace_back(region.name, region.marked);
    return out;
}

} // namespace vmdbg
