#include "VMInspector.h"

namespace vmdbg {

const Region* VMInspector::regionAt(uint64_t address) const {
    for (const Region& region : regionTable)
        if (region.contains(address)) return &region;
    return nullptr;
}

bool VMInspector::isInObjectMemory(uint64_t address) const {
    const Region* region = regionAt(address);
    return region && region->kind == Region::Kind::Objects;
}

bool VMInspector::isCodeAddress(uint64_t address) const {
    const Region* region = regionAt(address);
    return region && region->kind == Region::Kind::Code;
}

const char* regionKindName(Region::Kind kind) {
    switch (kind) {
    case Region::Kind::Objects: return "objects";
    case Region::Kind::Code:    return "code";
    case Region::Kind::Stack:   return "stack";
    case Region::Kind::Data:    break;
    }
    return "data";
}

std::string VMInspector::classifyAddress(uint64_t address) const {
    const Region* region = regionAt(address);
    return region ? region->name : std::string();
}

} // namespace vmdbg
