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

std::vector<ClassVariable> Inspector::classVariablesOf(
    const std::string& className) const {
    std::vector<ClassVariable> variables;
    if (const ClassEntry* entry = classNamed(className))
        for (const std::string& name : entry->classVariableNames)
            variables.push_back({name, std::nullopt});
    return variables;
}

std::optional<MethodEntry> Inspector::methodNamed(
    const std::string& className, const std::string& selector) const {
    for (MethodEntry& method : methodsOf(className))
        if (method.selector == selector) return std::move(method);
    return std::nullopt;
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

// The chain from the roots down starts the same way for every object; what
// tells a reader why one is kept is the last class on the way, since a class
// is where state outlives the objects that put it there.
std::vector<RetainerStep> Inspector::retainersOf(uint64_t oop) {
    std::vector<RetainerStep> chain;
    auto tracer = makeTracer();
    if (!tracer || !tracer->trace(true)) return chain;

    std::vector<uint64_t> path = tracer->pathTo(oop);
    size_t from = 0;
    for (size_t i = 0; i < path.size(); i++)
        if (classAt(path[i])) from = i;
    for (size_t i = from; i < path.size(); i++)
        chain.push_back(retainerStep(path[i]));
    return chain;
}

RetainerStep Inspector::retainerStep(uint64_t oop) const {
    RetainerStep step;
    step.oop = oop;
    const ClassEntry* named = classAt(oop);
    step.isClass = named != nullptr;
    auto object = objectFor(oop);
    if (object) step.className = object->className();
    if (named) step.detail = named->name;
    else if (object) step.detail = object->printString();
    return step;
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
