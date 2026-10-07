#include "VMInspector.h"

namespace vmdbg {

const Region* VMInspector::regionAt(uint64_t address) const {
    for (const Region& region : regionTable)
        if (region.contains(address)) return &region;
    return nullptr;
}

bool VMInspector::isInObjectMemory(uint64_t address) const {
    const Region* region = regionAt(address);
    return region && region->isObjectMemory;
}

bool VMInspector::isCodeAddress(uint64_t address) const {
    const Region* region = regionAt(address);
    return region && region->isCode;
}

std::string VMInspector::classifyAddress(uint64_t address) const {
    const Region* region = regionAt(address);
    return region ? region->name : std::string();
}

} // namespace vmdbg
