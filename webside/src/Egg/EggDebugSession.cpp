#include "EggDebugSession.h"
#include "../Json.h"
#include <chrono>
#include <thread>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>
#include <set>

namespace webside {

// Evaluator frame constants (used in getSmalltalkFrameBindings)
static constexpr int FRAME_TO_FIRST_ARG_DELTA = 2;
static constexpr int FRAME_TO_FIRST_TEMP_DELTA = 5;

// ---- Construction / Destruction ----

EggDebugSession::EggDebugSession() {
    debugger = std::make_unique<smalldbg::Debugger>(
        smalldbg::Mode::External, smalldbg::ARM64::instance());

    debugger->setLogCallback([](const std::string& msg) {
        std::cerr << "[dbg] " << msg << std::endl;
    });

    inspector = std::make_unique<egg::EggInspector>(debugger.get());
}

EggDebugSession::~EggDebugSession() {
    if (debugger && debugger->isAttached())
        debugger->detach();
}

// ---- Launch / Attach ----

bool EggDebugSession::launch(const std::string& eggPath,
                             const std::vector<std::string>& args) {
    std::cerr << "[egg] launching: " << eggPath << std::endl;
    auto status = debugger->launch(eggPath, args);
    if (status != smalldbg::Status::Ok) {
        std::cerr << "[egg] launch failed" << std::endl;
        return false;
    }
    std::cerr << "[egg] launched, pid=" << debugger->attachedPid().value_or(0) << std::endl;

    // Let the VM run for a while to initialize, then suspend.
    std::cerr << "[egg] resuming for 3s..." << std::endl;
    debugger->resume();
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cerr << "[egg] suspending..." << std::endl;
    if (!suspend()) {
        std::cerr << "[egg] suspend failed" << std::endl;
        return false;
    }
    std::cerr << "[egg] suspended" << std::endl;

    std::cerr << "[egg] locating runtime..." << std::endl;
    inspector->locateRuntime();
    std::cerr << "[egg] discovering classes..." << std::endl;
    inspector->discoverClasses();
    std::cerr << "[egg] launch complete" << std::endl;
    return true;
}

bool EggDebugSession::attach(int pid) {
    auto status = debugger->attach(static_cast<uintptr_t>(pid));
    if (status != smalldbg::Status::Ok)
        return false;

    inspector->locateRuntime();
    inspector->discoverClasses();
    return true;
}

void EggDebugSession::detach() {
    if (debugger)
        debugger->detach();
}

bool EggDebugSession::isActive() const {
    return debugger && debugger->isAttached();
}

std::optional<int> EggDebugSession::getPid() const {
    if (!debugger) return std::nullopt;
    auto p = debugger->attachedPid();
    if (p) return static_cast<int>(*p);
    return std::nullopt;
}

// ---- Debug control ----

bool EggDebugSession::resume() {
    return debugger->resume() == smalldbg::Status::Ok;
}

bool EggDebugSession::suspend() {
    if (debugger->isStopped())
        return true;

    if (debugger->suspend() != smalldbg::Status::Ok)
        return false;

    auto reason = debugger->waitForEvent(smalldbg::StopReason::None, 5000);
    if (reason == smalldbg::StopReason::None && !debugger->isStopped())
        return false;

    return true;
}

bool EggDebugSession::step() {
    return debugger->step() == smalldbg::Status::Ok;
}

// ---- State queries ----

std::string EggDebugSession::stopReasonStr(smalldbg::StopReason r) const {
    switch (r) {
        case smalldbg::StopReason::None:              return "running";
        case smalldbg::StopReason::ProcessCreated:    return "process_created";
        case smalldbg::StopReason::InitialBreakpoint: return "initial_breakpoint";
        case smalldbg::StopReason::Breakpoint:        return "breakpoint";
        case smalldbg::StopReason::SingleStep:        return "single_step";
        case smalldbg::StopReason::Exception:         return "exception";
        case smalldbg::StopReason::ProcessExit:       return "process_exit";
        default: return "unknown";
    }
}

std::string EggDebugSession::getStopReason() const {
    return stopReasonStr(debugger->getStopReason());
}

// ---- Class browsing API ----

Json EggDebugSession::classInfoToJson(const ClassEntry& entry) const {
    bool isMeta = entry.name.size() > 6 &&
                  entry.name.compare(entry.name.size() - 6, 6, " class") == 0;

    std::string def;
    if (isMeta) {
        def = entry.name;
    } else {
        def = entry.superclassName.empty() ? "nil" : entry.superclassName;
        def += " subclass: #" + entry.name;

        // Read instance variable names
        auto ivars = entry.species.instanceVariableNames();
        if (!ivars.empty()) {
            def += "\r\tinstanceVariableNames: '";
            for (size_t i = 0; i < ivars.size(); i++) {
                if (i > 0) def += " ";
                def += ivars[i];
            }
            def += "'";
        } else {
            def += "\r\tinstanceVariableNames: ''";
        }
    }

    auto j = Json::object()
        .set("name", entry.name)
        .set("class", isMeta ? "Metaclass" : entry.name + " class")
        .set("definition", def)
        .set("comment", "")
        .set("category", "")
        .set("variable", false)
        .set("package", determinePackage(entry))
        .set("hasNamedSlots", true)
        .set("hasIndexedSlots", false)
        .set("size", 0)
        .set("printString", entry.name);

    if (entry.superclassName.empty())
        j.set("superclass", nullptr);
    else
        j.set("superclass", entry.superclassName);

    return j;
}

std::string EggDebugSession::determinePackage(const ClassEntry& entry) const {
    if (!entry.species) return "";
    std::string modName = entry.species.moduleName();
    return modName.empty() ? "Kernel" : modName;
}

std::string EggDebugSession::listClasses(const std::string& root,
                                          bool namesOnly) const {
    auto& cache = inspector->getClassCache();
    if (cache.empty()) return "[]";

    std::vector<const ClassEntry*> classes;

    if (!root.empty()) {
        std::function<void(const std::string&)> collectSubtree;
        collectSubtree = [&](const std::string& name) {
            auto it = cache.find(name);
            if (it == cache.end()) return;
            classes.push_back(&it->second);
            inspector->collectSubclassesOf(name, collectSubtree);
        };
        collectSubtree(root);
    } else {
        for (auto& [name, entry] : cache)
            classes.push_back(&entry);
    }

    auto arr = Json::array();
    for (auto* entry : classes) {
        if (namesOnly)
            arr.add(entry->name);
        else
            arr.add(classInfoToJson(*entry));
    }
    return arr.dump();
}

std::string EggDebugSession::getClass(const std::string& name) const {
    auto& cache = inspector->getClassCache();

    // Handle metaclass names (e.g. "Array class")
    const std::string suffix = " class";
    if (name.size() > suffix.size() &&
        name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
        std::string baseName = name.substr(0, name.size() - suffix.size());
        auto it = cache.find(baseName);
        if (it == cache.end()) return "{}";

        std::string metaSuperclass;
        if (!it->second.superclassName.empty())
            metaSuperclass = it->second.superclassName + " class";
        else
            metaSuperclass = "Class";

        return Json::object()
            .set("name", name)
            .set("class", "Metaclass")
            .set("definition", name)
            .set("superclass", metaSuperclass)
            .set("comment", "")
            .set("category", "")
            .set("variable", false)
            .set("package", "")
            .set("hasNamedSlots", true)
            .set("hasIndexedSlots", false)
            .set("size", 0)
            .set("printString", name)
            .dump();
    }

    auto it = cache.find(name);
    if (it == cache.end()) return "{}";
    return classInfoToJson(it->second).dump();
}

std::string EggDebugSession::getSubclasses(const std::string& name) const {
    auto& cache = inspector->getClassCache();
    auto arr = Json::array();
    for (auto& [childName, entry] : cache) {
        if (entry.superclassName == name)
            arr.add(classInfoToJson(entry));
    }
    return arr.dump();
}

std::string EggDebugSession::getSuperclasses(const std::string& name) const {
    auto& cache = inspector->getClassCache();
    auto arr = Json::array();
    std::string current = name;
    std::set<std::string> visited;

    while (!current.empty()) {
        if (visited.count(current)) break;
        visited.insert(current);

        auto it = cache.find(current);
        if (it == cache.end()) break;
        current = it->second.superclassName;
        if (current.empty()) break;

        auto superIt = cache.find(current);
        if (superIt == cache.end()) break;
        arr.add(classInfoToJson(superIt->second));
    }
    return arr.dump();
}

std::string EggDebugSession::getVariables(const std::string& name) const {
    auto& cache = inspector->getClassCache();
    auto arr = Json::array();

    // Collect all instance variables from the class and its superclass chain
    std::vector<std::string> chain;
    std::string current = name;
    std::set<std::string> visited;
    while (!current.empty() && !visited.count(current)) {
        visited.insert(current);
        chain.push_back(current);
        auto it = cache.find(current);
        if (it == cache.end()) break;
        current = it->second.superclassName;
    }

    // Walk from root to leaf so inherited vars come first
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        auto classIt = cache.find(*it);
        if (classIt == cache.end()) continue;
        auto ivars = classIt->second.species.instanceVariableNames();
        for (auto& varName : ivars) {
            arr.add(Json::object()
                .set("name", varName)
                .set("class", *it)
                .set("type", "instance"));
        }
    }
    return arr.dump();
}

std::string EggDebugSession::getInstanceVariables(const std::string& name) const {
    auto* entry = inspector->findClassByName(name);
    if (!entry) return "[]";

    auto ivars = entry->species.instanceVariableNames();
    auto arr = Json::array();
    for (auto& varName : ivars) {
        arr.add(Json::object()
            .set("name", varName)
            .set("class", name)
            .set("type", "instance"));
    }
    return arr.dump();
}

std::string EggDebugSession::getClassVariables(const std::string& name) const {
    return "[]";
}

std::string EggDebugSession::getCategories(const std::string& name) const {
    return "[]";
}

std::string EggDebugSession::getUsedCategories(const std::string& name) const {
    return "[]";
}

std::string EggDebugSession::getSelectors(const std::string& name) const {
    auto* entry = inspector->findClassByName(name);
    if (!entry) return "[]";

    auto methodEntries = inspector->readMethodDictionary(entry->species);
    auto arr = Json::array();
    for (auto& [sel, method] : methodEntries)
        arr.add(sel);
    return arr.dump();
}

std::string EggDebugSession::getMethods(const std::string& name) const {
    auto* entry = inspector->findClassByName(name);
    if (!entry) return "[]";

    auto methodEntries = inspector->readMethodDictionary(entry->species);
    auto arr = Json::array();
    for (auto& [sel, method] : methodEntries) {
        arr.add(Json::object()
            .set("selector", sel)
            .set("methodClass", name)
            .set("category", "")
            .set("source", method.sourceCode())
            .set("author", "")
            .set("timestamp", "")
            .set("package", ""));
    }
    return arr.dump();
}

std::string EggDebugSession::getMethod(const std::string& className,
                                        const std::string& selector) const {
    auto* entry = inspector->findClassByName(className);
    if (!entry) return "{}";

    auto methodEntries = inspector->readMethodDictionary(entry->species);
    for (auto& [sel, method] : methodEntries) {
        if (sel == selector) {
            return Json::object()
                .set("selector", sel)
                .set("methodClass", className)
                .set("category", "")
                .set("source", method.sourceCode())
                .set("author", "")
                .set("timestamp", "")
                .set("package", "")
                .dump();
        }
    }
    return "{}";
}

// ---- Search ----

static bool matchCondition(const std::string& haystack, const std::string& needle,
                           const std::string& condition, bool ignoreCase) {
    std::string h = haystack;
    std::string n = needle;
    if (ignoreCase) {
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    }
    if (condition == "beginning")
        return h.size() >= n.size() && h.compare(0, n.size(), n) == 0;
    if (condition == "ending")
        return h.size() >= n.size() && h.compare(h.size() - n.size(), n.size(), n) == 0;
    // "similar" or default: substring match
    return h.find(n) != std::string::npos;
}

std::string EggDebugSession::search(const std::string& text, bool ignoreCase,
                                     const std::string& condition,
                                     const std::string& type) const {
    if (text.empty()) return "[]";

    auto& cache = inspector->getClassCache();
    auto arr = Json::array();
    bool searchClasses = (type == "all" || type == "class");
    bool searchSelectors = (type == "all" || type == "selector");

    if (searchClasses) {
        for (auto& [name, entry] : cache) {
            if (matchCondition(name, text, condition, ignoreCase))
                arr.add(Json::object().set("type", "class").set("text", name));
        }
    }

    if (searchSelectors) {
        std::set<std::string> seen;
        for (auto& [name, entry] : cache) {
            auto methods = inspector->readMethodDictionary(entry.species);
            for (auto& [sel, method] : methods) {
                if (seen.count(sel)) continue;
                if (matchCondition(sel, text, condition, ignoreCase)) {
                    seen.insert(sel);
                    arr.add(Json::object().set("type", "selector").set("text", sel));
                }
            }
        }
    }

    return arr.dump();
}

// ---- Frame listing (native C++ stack) ----

std::string EggDebugSession::listFrames(size_t maxFrames) const {
    auto process = debugger->getProcess();
    if (!process) return "[]";

    auto mainThread = process->primaryThread();
    if (!mainThread) return "[]";

    smalldbg::StackTrace trace(mainThread.get());
    if (trace.unwind(maxFrames) != smalldbg::Status::Ok)
        return "[]";

    const auto& frames = trace.getFrames();
    auto arr = Json::array();
    for (size_t i = 0; i < frames.size(); i++) {
        const auto& f = *frames[i];
        std::string label;
        if (!f.moduleName.empty() && !f.functionName.empty())
            label = f.moduleName + "!" + f.functionName;
        else if (!f.functionName.empty())
            label = f.functionName;
        else
            label = "<unknown>";

        arr.add(Json::object()
            .set("index", static_cast<int>(i + 1))
            .set("label", label));
    }
    return arr.dump();
}

std::string EggDebugSession::getFrameDetail(int index) const {
    auto process = debugger->getProcess();
    if (!process) return "{}";

    auto mainThread = process->primaryThread();
    if (!mainThread) return "{}";

    smalldbg::StackTrace trace(mainThread.get());
    if (trace.unwind(256) != smalldbg::Status::Ok)
        return "{}";

    const auto& frames = trace.getFrames();
    if (index < 1 || index > static_cast<int>(frames.size()))
        return "{}";

    const auto& f = *frames[index - 1];
    std::string label;
    if (!f.moduleName.empty() && !f.functionName.empty())
        label = f.moduleName + "!" + f.functionName;
    else if (!f.functionName.empty())
        label = f.functionName;
    else
        label = "<unknown>";

    std::string modName = f.moduleName.empty() ? "<native>" : f.moduleName;

    auto j = Json::object()
        .set("index", index)
        .set("label", label)
        .set("class", Json::object()
            .set("name", modName)
            .set("definition", "")
            .set("superclass", Json())
            .set("comment", "Native module")
            .set("category", "native")
            .set("variable", false)
            .set("package", ""))
        .set("method", Json::object()
            .set("selector", f.functionName)
            .set("methodClass", f.moduleName)
            .set("category", "native")
            .set("source", f.functionName + " (native code)")
            .set("author", "")
            .set("timestamp", "")
            .set("package", ""))
        .set("interval", Json::object().set("start", 0).set("end", 0));

    return j.dump();
}

std::string EggDebugSession::getFrameBindings(int index) const {
    // For now, return empty bindings for native frames
    return "[]";
}

// ---- Green thread management ----

void EggDebugSession::refreshGreenThreads() {
    greenThreads.clear();

    auto st = inspector->readEvaluatorState();
    if (!st.valid) return;

    GreenThread gt;
    gt.id = 1;
    gt.name = "main";
    gt.state = st;
    gt.frames = inspector->walkSmalltalkFrames(st);

    greenThreads.push_back(std::move(gt));
}

int EggDebugSession::greenThreadCount() const {
    return static_cast<int>(greenThreads.size());
}

std::string EggDebugSession::getGreenThreadName(int threadIndex) const {
    if (threadIndex < 0 || threadIndex >= static_cast<int>(greenThreads.size()))
        return "unknown";
    return greenThreads[threadIndex].name;
}

static std::string frameLabel(const EggDebugSession::SmalltalkFrame& f) {
    if (f.isBlock)
        return "[] in " + f.className + ">>" + f.selector;
    if (!f.className.empty() && !f.selector.empty())
        return f.className + ">>" + f.selector;
    if (!f.selector.empty())
        return f.selector;
    return "<unknown>";
}

std::string EggDebugSession::listSmalltalkFrames(int threadIndex) const {
    if (threadIndex < 0 || threadIndex >= static_cast<int>(greenThreads.size()))
        return "[]";

    const auto& gt = greenThreads[threadIndex];
    auto arr = Json::array();
    for (const auto& f : gt.frames) {
        arr.add(Json::object()
            .set("index", f.index)
            .set("label", frameLabel(f)));
    }
    return arr.dump();
}

std::string EggDebugSession::getSmalltalkFrameDetail(int threadIndex,
                                                     int frameIndex) const {
    if (threadIndex < 0 || threadIndex >= static_cast<int>(greenThreads.size()))
        return "{}";

    const auto& gt = greenThreads[threadIndex];
    if (frameIndex < 1 || frameIndex > static_cast<int>(gt.frames.size()))
        return "{}";

    const auto& f = gt.frames[frameIndex - 1];
    std::string label = frameLabel(f);

    std::string source;
    if (f.method)
        source = f.method.sourceCode();

    auto j = Json::object()
        .set("index", f.index)
        .set("label", label)
        .set("class", Json::object()
            .set("name", f.className.empty() ? "<unknown>" : f.className)
            .set("definition", "")
            .set("superclass", Json())
            .set("comment", "")
            .set("category", "")
            .set("variable", false)
            .set("package", ""))
        .set("method", Json::object()
            .set("selector", f.selector)
            .set("methodClass", f.className)
            .set("category", "")
            .set("source", source.empty() ? label : source)
            .set("author", "")
            .set("timestamp", "")
            .set("package", ""))
        .set("interval", Json::object().set("start", 0).set("end", 0));

    return j.dump();
}

std::string EggDebugSession::getSmalltalkFrameBindings(int threadIndex,
                                                       int frameIndex) const {
    if (threadIndex < 0 || threadIndex >= static_cast<int>(greenThreads.size()))
        return "[]";

    const auto& gt = greenThreads[threadIndex];
    if (frameIndex < 1 || frameIndex > static_cast<int>(gt.frames.size()))
        return "[]";

    const auto& f = gt.frames[frameIndex - 1];
    auto arr = Json::array();

    // self binding
    arr.add(Json::object()
        .set("name", "self")
        .set("value", inspector->describeRemoteObject(f.receiver))
        .set("type", "special"));

    if (!f.method)
        return arr.dump();

    int argCount = f.method.argCount();
    int tempCount = f.method.tempCount();

    // Arguments: _stack[bp + FRAME_TO_FIRST_ARG_DELTA + i - 1] (0-based)
    for (int i = 0; i < argCount && i < 20; i++) {
        uint64_t argVal = inspector->readStackSlot(gt.state,
            f.bp + FRAME_TO_FIRST_ARG_DELTA + i);
        arr.add(Json::object()
            .set("name", "arg" + std::to_string(i + 1))
            .set("value", inspector->describeRemoteObject(
                              inspector->objectAt(argVal)))
            .set("type", "argument"));
    }

    // Temporaries: _stack[bp - FRAME_TO_FIRST_TEMP_DELTA - i - 1] (0-based)
    for (int i = 0; i < tempCount && i < 20; i++) {
        uint64_t tempVal = inspector->readStackSlot(gt.state,
            f.bp - FRAME_TO_FIRST_TEMP_DELTA - i);
        arr.add(Json::object()
            .set("name", "temp" + std::to_string(i + 1))
            .set("value", inspector->describeRemoteObject(
                              inspector->objectAt(tempVal)))
            .set("type", "temporary"));
    }

    return arr.dump();
}

} // namespace webside
