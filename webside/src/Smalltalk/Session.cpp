#include "Session.h"
#include "Json.h"
#include "Smalltalk/InspectorJson.h"

#include <smalldbg/Arch.h>
#include <smalldbg/Debugger.h>
#include <smalldbg/DisassemblyAnnotator.h>
#include <smalldbg/StackFrame.h>
#include <smalldbg/StackTrace.h>
#include "Smalltalk/FrameUnwinder.h"

#include <algorithm>
#include <cctype>
#include <set>

namespace smalltalk {

using webside::Json;

namespace {

const std::string metaclassSuffix = " class";

std::string lowercase(std::string text) {
    for (char& c : text)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}

// Webside's conditions are "beginning", "ending", and "including" or
// "similar", which both mean a substring.
bool matches(const std::string& candidate, const std::string& text,
             const std::string& condition, bool ignoreCase) {
    const std::string h = ignoreCase ? lowercase(candidate) : candidate;
    const std::string n = ignoreCase ? lowercase(text) : text;
    if (h.size() < n.size()) return false;
    if (condition == "beginning") return h.compare(0, n.size(), n) == 0;
    if (condition == "ending")
        return h.compare(h.size() - n.size(), n.size(), n) == 0;
    return h.find(n) != std::string::npos;
}

// A word in object memory names an object; one anywhere else, a native
// symbol at most.
class ObjectAnnotationSource : public smalldbg::SymbolAnnotationSource {
public:
    ObjectAnnotationSource(smalldbg::Debugger& debugger, const Inspector& objects)
        : SymbolAnnotationSource(debugger), inspector(objects) {}

    std::string dataLabel(smalldbg::Address address) const override {
        if (inspector.isInObjectMemory(address)) {
            auto object = inspector.objectFor(address);
            if (object && object->isHeapObject()) return object->printString();
        }
        return SymbolAnnotationSource::dataLabel(address);
    }

private:
    const Inspector& inspector;
};

Json variableJson(const std::string& name, const std::string& className,
                  const char* type) {
    return Json::object().set("name", name)
                         .set("class", className)
                         .set("type", type);
}

} // namespace

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

// Reading a running target blocks until it stops, so a running target's
// processes are left as they were.
void Session::refreshGreenThreads() {
    if (!debugger().isStopped()) return;
    if (greenThreadsVersion == debugger().stateVersion()) return;
    greenStacks.clear();
    if (readGreenThreads()) greenThreadsVersion = debugger().stateVersion();
}

smalldbg::StackTrace* Session::greenStack(int threadIndex) const {
    const_cast<Session*>(this)->refreshGreenThreads();
    auto found = greenStacks.find(threadIndex);
    if (found != greenStacks.end()) return found->second.get();

    auto frames = readGreenFrames(threadIndex);
    if (frames.empty()) return nullptr;
    auto& stack = greenStacks[threadIndex];
    stack = std::make_unique<smalldbg::StackTrace>(nullptr, std::move(frames));
    return stack.get();
}

// ---------------------------------------------------------------------------
// Class browsing
// ---------------------------------------------------------------------------

bool Session::discoverClasses() {
    Inspector& inspector = smalltalkInspector();
    return inspector.discoverClasses();
}

bool Session::isMetaclassName(const std::string& name) {
    return name.size() > metaclassSuffix.size()
        && name.compare(name.size() - metaclassSuffix.size(),
                        metaclassSuffix.size(), metaclassSuffix) == 0;
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
        .set("variable", entry.variable)
        .set("package", entry.package);

    if (entry.superclassName.empty())
        json.set("superclass", nullptr);
    else
        json.set("superclass", entry.superclassName);
    if (entry.oop != 0) json.set("oop", addressHex(entry.oop));
    return json;
}

// A method whose source cannot be found still has a heading worth showing.
Json Session::methodJson(const MethodEntry& method) const {
    std::string source = smalltalkInspector().sourceOf(method);
    auto json = Json::object()
        .set("selector", method.selector)
        .set("methodClass", method.className)
        .set("category", method.category)
        .set("source", source.empty()
                           ? method.className + ">>" + method.selector
                           : source)
        .set("hasSource", !source.empty())
        .set("author", "")
        .set("timestamp", "")
        .set("package", "");
    if (method.oop != 0) json.set("oop", addressHex(method.oop));
    return json;
}

std::optional<ClassEntry> Session::entryNamed(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    if (const ClassEntry* entry = inspector.classNamed(name)) return *entry;
    if (!isMetaclassName(name)) return std::nullopt;

    const ClassEntry* base = inspector.classNamed(
        name.substr(0, name.size() - metaclassSuffix.size()));
    if (!base) return std::nullopt;
    ClassEntry meta;
    meta.name = name;
    meta.superclassName = base->superclassName.empty()
        ? "Class" : base->superclassName + " class";
    meta.category = base->category;
    meta.package = base->package;
    return meta;
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
        array.add(namesOnly ? Json::string(name) : classJson(entry));
    }
    return array.dump();
}

std::string Session::getClass(const std::string& name) const {
    auto entry = entryNamed(name);
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

std::string Session::printed(uint64_t oop) const {
    return smalltalkInspector().printed(oop);
}

// Webside asks for a class's variables as one list of named slots, inherited
// ones first, each with the class that defines it; which are instance and
// which are class variables is in the "type" field.
std::string Session::getVariables(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    if (!inspector.classNamed(name)) return "[]";

    std::vector<std::string> chain = inspector.superclassesOf(name);
    std::reverse(chain.begin(), chain.end());
    chain.push_back(name);

    auto array = Json::array();
    for (const std::string& owner : chain) {
        const ClassEntry* entry = inspector.classNamed(owner);
        for (const std::string& variable : entry->instanceVariableNames)
            array.add(variableJson(variable, owner, "instance"));
    }
    addClassVariables(array, name);
    return array.dump();
}

std::string Session::getInstanceVariables(const std::string& name) const {
    Inspector& inspector = smalltalkInspector();
    const ClassEntry* entry = inspector.classNamed(name);
    if (!entry) return "[]";

    auto array = Json::array();
    for (const std::string& variable : entry->instanceVariableNames)
        array.add(variableJson(variable, name, "instance"));
    return array.dump();
}

void Session::addClassVariables(Json& array, const std::string& name) const {
    for (const ClassVariable& variable :
         smalltalkInspector().classVariablesOf(name)) {
        Json json = variableJson(variable.name, name, "class");
        if (variable.value) json.set("value", printed(*variable.value));
        array.add(std::move(json));
    }
}

std::string Session::getClassVariables(const std::string& name) const {
    auto array = Json::array();
    addClassVariables(array, name);
    return array.dump();
}

std::vector<std::string> Session::categoriesOf(const std::string& name) const {
    std::set<std::string> categories;
    for (const MethodEntry& method : smalltalkInspector().methodsOf(name))
        if (!method.category.empty()) categories.insert(method.category);
    return {categories.begin(), categories.end()};
}

std::string Session::getCategories(const std::string& name) const {
    auto array = Json::array();
    for (const std::string& category : categoriesOf(name))
        array.add(category);
    return array.dump();
}

// Returns the categories in use from the class up to the root, which is what a
// browser offers when a method is filed.
std::string Session::getUsedCategories(const std::string& name) const {
    std::vector<std::string> chain = smalltalkInspector().superclassesOf(name);
    chain.insert(chain.begin(), name);

    std::set<std::string> categories;
    for (const std::string& owner : chain)
        for (const std::string& category : categoriesOf(owner))
            categories.insert(category);

    auto array = Json::array();
    for (const std::string& category : categories)
        array.add(category);
    return array.dump();
}

std::string Session::getSelectors(const std::string& name) const {
    auto array = Json::array();
    for (const MethodEntry& method : smalltalkInspector().methodsOf(name))
        array.add(method.selector);
    return array.dump();
}

std::string Session::getMethods(const std::string& name) const {
    auto array = Json::array();
    for (const MethodEntry& method : smalltalkInspector().methodsOf(name))
        array.add(methodJson(method));
    return array.dump();
}

std::string Session::getMethod(const std::string& className,
                               const std::string& selector) const {
    auto method = smalltalkInspector().methodNamed(className, selector);
    return method ? methodJson(*method).dump() : "{}";
}

// A block runs in its method's activation, and says which of its blocks.
void Session::addSmalltalkFrameDetail(Json& json,
                                      const smalldbg::StackFrame& frame) const {
    webside::WebsideSession::addSmalltalkFrameDetail(json, frame);
    const auto* running = dynamic_cast<const FrameMetadata*>(frame.metadata.get());
    if (!running) return;

    if (auto entry = entryNamed(running->className)) json.set("class", classJson(*entry));
    if (auto method = smalltalkInspector().methodNamed(running->className,
                                                        running->selector)) {
        Json described = methodJson(*method);
        if (running->isBlock && running->blockIndex >= 0)
            described.set("selector", method->selector + " [block "
                          + std::to_string(running->blockIndex) + "]");
        json.set("hasSource", described["hasSource"].asBool());
        json.set("method", described);
    }
    if (running->receiver != 0) json.set("receiver", printed(running->receiver));
    if (running->instruction >= 0) json.set("instruction", running->instruction);
}

namespace {

// Returns the keywords of a keyword selector, or one name for a binary
// selector's argument, which has no keyword.
std::vector<std::string> keywordsOf(const std::string& selector) {
    std::vector<std::string> names;
    if (selector.find(':') != std::string::npos) {
        size_t start = 0;
        for (size_t i = 0; i < selector.size(); i++) {
            if (selector[i] != ':') continue;
            names.push_back(selector.substr(start, i - start));
            start = i + 1;
        }
    } else if (!selector.empty()
               && !std::isalpha(static_cast<unsigned char>(selector[0]))
               && selector[0] != '_') {
        names.push_back("arg");
    }
    return names;
}

} // namespace

// A block's arguments, and any the selector does not account for, are
// numbered instead.
std::string Session::buildFrameArgumentsJson(const smalldbg::StackFrame& frame) const {
    const auto* running = dynamic_cast<const FrameMetadata*>(frame.metadata.get());
    if (!running || running->arguments.empty()) return "[]";

    const auto& values = running->arguments;
    std::vector<std::string> names;
    if (!running->isBlock) names = keywordsOf(running->selector);
    auto array = Json::array();
    for (size_t i = 0; i < values.size(); i++) {
        auto entry = Json::object()
            .set("name", names.size() == values.size() ? names[i]
                                                       : "arg" + std::to_string(i + 1))
            .set("value", addressHex(values[i]));
        addPrintString(entry, values[i]);
        array.add(std::move(entry));
    }
    return array.dump();
}


void Session::describeRegister(Json& entry, const smalldbg::StackFrame& frame,
                               const smalldbg::RegisterValue& reg) const {
    webside::WebsideSession::describeRegister(entry, frame, reg);
    if (reg.role == smalldbg::RegisterValue::Role::Other)
        addPrintString(entry, *reg.value);
}

// A register or a slot can point into an object rather than at its start, and
// such a value does not print.
void Session::addPrintString(Json& entry, uint64_t value) const {
    if (value == 0 || !mayBeObject(value)) return;
    try {
        std::string text = printed(value);
        if (!text.empty()) entry.set("printString", text);
    } catch (...) {}
}

bool Session::mayBeObject(uint64_t value) const {
    const vmdbg::Region* region = smalltalkInspector().regionAt(value);
    return region && region->kind == vmdbg::Region::Kind::Objects
           && !region->isFree(value);
}

std::unique_ptr<smalldbg::AnnotationSource> Session::annotationSource() const {
    return std::make_unique<ObjectAnnotationSource>(debugger(), smalltalkInspector());
}

std::string Session::describeObject(uint64_t oop, int firstSlot,
                                    int maxSlots) const {
    Json json = webside::inspectObjectJson(smalltalkInspector(), oop,
                                           firstSlot, maxSlots);
    if (json["error"].isNull() && !json["immediate"].asBool())
        describeHeader(json, oop);
    return json.dump();
}

// Finds class names first, then selectors from both sides of every class,
// each selector once.
std::string Session::search(const std::string& text, bool ignoreCase,
                            const std::string& condition,
                            const std::string& type) const {
    if (text.empty()) return "[]";
    Inspector& inspector = smalltalkInspector();
    const bool all = type.empty() || type == "all";

    auto array = Json::array();
    if (all || type == "class") {
        for (const auto& [name, entry] : inspector.classes())
            if (!isMetaclassName(name)
                && matches(name, text, condition, ignoreCase))
                array.add(Json::object().set("type", "class").set("text", name));
    }

    if (all || type == "selector") {
        std::set<std::string> seen;
        for (const auto& [name, entry] : inspector.classes()) {
            if (isMetaclassName(name)) continue;
            for (const std::string& side : {name, name + " class"})
                for (const MethodEntry& method : inspector.methodsOf(side))
                    if (matches(method.selector, text, condition, ignoreCase)
                        && seen.insert(method.selector).second)
                        array.add(Json::object().set("type", "selector")
                                                .set("text", method.selector));
        }
    }
    return array.dump();
}

} // namespace smalltalk
