#include "Session.h"
#include "Json.h"

#include <smalldbg/Debugger.h>

#include <algorithm>
#include <set>

namespace smalltalk {

using webside::Json;

bool Session::isActive() const {
    return debugger().isAttached();
}

std::optional<int> Session::getPid() const {
    auto pid = debugger().attachedPid();
    if (!pid) return std::nullopt;
    return static_cast<int>(*pid);
}

// A client can act on three states: no target, a stopped one, or a running
// one that cannot be read.
std::string Session::getStopReason() const {
    if (!isActive()) return "detached";
    return debugger().isStopped() ? "stopped" : "running";
}

// ---------------------------------------------------------------------------
// Class browsing
// ---------------------------------------------------------------------------

bool Session::discoverClasses() {
    Inspector& inspector = smalltalkInspector();
    return inspector.discoverClasses();
}

bool Session::isMetaclassName(const std::string& name) {
    static const std::string suffix = " class";
    return name.size() > suffix.size()
        && name.compare(name.size() - suffix.size(), suffix.size(),
                        suffix) == 0;
}

std::string Session::classDefinition(const ClassEntry& entry) {
    if (isMetaclassName(entry.name)) return entry.name;

    std::string definition =
        entry.superclassName.empty() ? "nil" : entry.superclassName;
    definition += " subclass: #" + entry.name;
    definition += "\r\tinstanceVariableNames: '";
    for (size_t i = 0; i < entry.instanceVariableNames.size(); i++) {
        if (i > 0) definition += " ";
        definition += entry.instanceVariableNames[i];
    }
    definition += "'";
    if (!entry.category.empty())
        definition += "\r\tcategory: '" + entry.category + "'";
    return definition;
}

Json Session::classJson(const ClassEntry& entry) const {
    bool metaclass = isMetaclassName(entry.name);
    auto json = Json::object()
        .set("name", entry.name)
        .set("class", metaclass ? "Metaclass" : entry.name + " class")
        .set("definition", classDefinition(entry))
        .set("printString", entry.name)
        .set("hasNamedSlots", true)
        .set("hasIndexedSlots", false)
        .set("size", 0)
        .set("comment", "")
        .set("category", entry.category)
        .set("variable", false)
        .set("package", "");

    if (entry.superclassName.empty())
        json.set("superclass", nullptr);
    else
        json.set("superclass", entry.superclassName);
    return json;
}

std::string Session::rootClassName() const {
    Inspector& inspector = smalltalkInspector();
    for (const auto& [name, entry] : inspector.classes())
        if (entry.superclassName.empty() && !isMetaclassName(name)) return name;
    return {};
}

Json Session::classTreeJson(const std::string& name, bool namesOnly,
                            int depth) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return Json::null();

    Json node = namesOnly ? Json::object().set("name", entry->name)
                          : classJson(*entry);
    if (depth == 0) return node;

    auto children = Json::array();
    for (const std::string& child : inspector.subclassesOf(name)) {
        int below = depth < 0 ? -1 : depth - 1;
        Json subtree = classTreeJson(child, namesOnly, below);
        if (!subtree.isNull()) children.add(std::move(subtree));
    }
    node.set("subclasses", children);
    return node;
}

std::string Session::listClasses(const std::string& root, bool namesOnly,
                                 bool tree, int depth) const {
    Inspector& inspector = smalltalkInspector();
    if (inspector.classes().empty()) inspector.discoverClasses();
    if (inspector.classes().empty()) return "[]";

    if (tree) {
        std::string from = root.empty() ? rootClassName() : root;
        Json subtree = classTreeJson(from, namesOnly, depth);
        if (subtree.isNull()) return "[]";
        return Json::array().add(std::move(subtree)).dump();
    }

    auto array = Json::array();
    for (const auto& [name, entry] : inspector.classes()) {
        if (!root.empty() && name != root) {
            auto chain = inspector.superclassesOf(name);
            if (std::find(chain.begin(), chain.end(), root) == chain.end())
                continue;
        }
        array.add(namesOnly ? Json::object().set("name", name)
                            : classJson(entry));
    }
    return array.dump();
}

std::string Session::getClass(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return "{}";
    return classJson(*entry).dump();
}

std::string Session::getSubclasses(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    auto array = Json::array();
    for (const std::string& child : inspector.subclassesOf(name)) {
        if (const ClassEntry* entry = inspector.classNamed(child))
            array.add(classJson(*entry));
    }
    return array.dump();
}

std::string Session::getSuperclasses(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    auto array = Json::array();
    for (const std::string& parent : inspector.superclassesOf(name)) {
        if (const ClassEntry* entry = inspector.classNamed(parent))
            array.add(classJson(*entry));
    }
    return array.dump();
}

// Webside asks for a class's variables as one list of named slots; which of
// them are instance and which are class variables is in the "type" field.
std::string Session::getVariables(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return "[]";

    auto array = Json::array();
    for (const std::string& variable : entry->instanceVariableNames)
        array.add(Json::object().set("name", variable)
                                .set("class", name)
                                .set("type", "instance"));
    for (const std::string& variable : entry->classVariableNames)
        array.add(Json::object().set("name", variable)
                                .set("class", name)
                                .set("type", "class"));
    return array.dump();
}

std::string Session::getInstanceVariables(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return "[]";

    auto array = Json::array();
    for (const std::string& variable : entry->instanceVariableNames)
        array.add(Json::object().set("name", variable)
                                .set("class", name)
                                .set("type", "instance"));
    return array.dump();
}

std::string Session::getClassVariables(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return "[]";

    auto array = Json::array();
    for (const std::string& variable : entry->classVariableNames)
        array.add(Json::object().set("name", variable)
                                .set("class", name)
                                .set("type", "class"));
    return array.dump();
}

std::string Session::getCategories(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry || entry->category.empty()) return "[]";
    return Json::array().add(Json::string(entry->category)).dump();
}

std::string Session::getUsedCategories(const std::string& name) const {
    return getCategories(name);
}

} // namespace smalltalk
