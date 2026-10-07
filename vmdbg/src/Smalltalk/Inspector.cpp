#include "Inspector.h"

#include <algorithm>

namespace smalltalk {

const ClassEntry* Inspector::classNamed(const std::string& name) const {
    auto found = classTable.find(name);
    return found == classTable.end() ? nullptr : &found->second;
}

const ClassEntry* Inspector::classAt(uint64_t oop) const {
    for (const auto& [name, entry] : classTable)
        if (entry.oop == oop) return &entry;
    return nullptr;
}

std::vector<std::string> Inspector::subclassesOf(const std::string& name) const {
    const ClassEntry* parent = classNamed(name);
    if (!parent) return {};

    std::vector<std::string> found;
    for (const auto& [childName, entry] : classTable)
        if (entry.superclass == parent->oop) found.push_back(childName);
    std::sort(found.begin(), found.end());
    return found;
}

// Walks up rather than down, so a broken link ends the chain instead of
// looping: a class whose superclass is itself would otherwise never terminate.
std::vector<std::string> Inspector::superclassesOf(const std::string& name) const {
    std::vector<std::string> chain;
    const ClassEntry* entry = classNamed(name);
    while (entry && entry->superclass != 0) {
        const ClassEntry* parent = classAt(entry->superclass);
        if (!parent) break;
        if (std::find(chain.begin(), chain.end(), parent->name) != chain.end()) break;
        chain.push_back(parent->name);
        entry = parent;
    }
    return chain;
}

} // namespace smalltalk
