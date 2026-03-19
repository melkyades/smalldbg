#include "EggDebugSession.h"
#include "../Json.h"
#include <chrono>
#include <thread>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>

namespace webside {

// Evaluator frame constants (used in getSmalltalkFrameBindings)
static constexpr int FRAME_TO_FIRST_ARG_DELTA = 2;
static constexpr int FRAME_TO_FIRST_TEMP_DELTA = 5;

// Parse a Smalltalk method header to extract argument and temporary names.
// Handles unary (e.g. "foo"), binary (e.g. "+ other"), and keyword
// (e.g. "at: key put: value") selectors, plus temp declarations (| a b c |).
struct MethodNames {
    std::vector<std::string> args;
    std::vector<std::string> temps;
};

static std::string nextWord(const std::string& src, size_t& pos) {
    while (pos < src.size() && std::isspace(static_cast<unsigned char>(src[pos])))
        pos++;
    if (pos >= src.size()) return "";
    // String literal — skip
    if (src[pos] == '\'') return "";
    // Identifier
    if (std::isalpha(static_cast<unsigned char>(src[pos])) ||
        src[pos] == '_') {
        size_t start = pos;
        while (pos < src.size() &&
               (std::isalnum(static_cast<unsigned char>(src[pos])) ||
                src[pos] == '_'))
            pos++;
        return src.substr(start, pos - start);
    }
    return "";
}

static MethodNames parseMethodHeader(const std::string& src) {
    MethodNames names;
    size_t pos = 0;

    // Skip leading whitespace
    while (pos < src.size() && std::isspace(static_cast<unsigned char>(src[pos])))
        pos++;
    if (pos >= src.size()) return names;

    // Determine selector kind by first non-space char
    char first = src[pos];
    if (std::isalpha(static_cast<unsigned char>(first)) || first == '_') {
        // Could be unary or keyword
        std::string word = nextWord(src, pos);
        while (pos < src.size() &&
               std::isspace(static_cast<unsigned char>(src[pos])))
            pos++;
        if (pos < src.size() && src[pos] == ':') {
            // Keyword selector: "key1: arg1 key2: arg2 ..."
            pos++; // skip ':'
            std::string arg = nextWord(src, pos);
            if (!arg.empty()) names.args.push_back(arg);
            // Continue for more keywords
            while (pos < src.size()) {
                while (pos < src.size() &&
                       std::isspace(static_cast<unsigned char>(src[pos])))
                    pos++;
                if (pos >= src.size()) break;
                // Next keyword or temp bar
                if (src[pos] == '|' || src[pos] == '<' ||
                    src[pos] == '[' || src[pos] == '^')
                    break;
                std::string kw = nextWord(src, pos);
                if (kw.empty()) break;
                while (pos < src.size() &&
                       std::isspace(static_cast<unsigned char>(src[pos])))
                    pos++;
                if (pos < src.size() && src[pos] == ':') {
                    pos++; // skip ':'
                    std::string a = nextWord(src, pos);
                    if (!a.empty()) names.args.push_back(a);
                } else {
                    break;
                }
            }
        }
        // else: unary selector, no args
    } else {
        // Binary selector (e.g. +, -, ==)
        while (pos < src.size() &&
               !std::isspace(static_cast<unsigned char>(src[pos])) &&
               !std::isalpha(static_cast<unsigned char>(src[pos])) &&
               src[pos] != '_')
            pos++;
        std::string arg = nextWord(src, pos);
        if (!arg.empty()) names.args.push_back(arg);
    }

    // Parse temp declarations: | name1 name2 ... |
    while (pos < src.size() && std::isspace(static_cast<unsigned char>(src[pos])))
        pos++;

    // Skip pragmas: <primitive: ...>
    while (pos < src.size() && src[pos] == '<') {
        size_t end = src.find('>', pos);
        if (end == std::string::npos) break;
        pos = end + 1;
        while (pos < src.size() &&
               std::isspace(static_cast<unsigned char>(src[pos])))
            pos++;
    }

    // Skip string literal (e.g. "docstring")
    while (pos < src.size() && src[pos] == '"') {
        size_t end = src.find('"', pos + 1);
        if (end == std::string::npos) break;
        pos = end + 1;
        while (pos < src.size() &&
               std::isspace(static_cast<unsigned char>(src[pos])))
            pos++;
    }

    if (pos < src.size() && src[pos] == '|') {
        pos++; // skip opening |
        while (pos < src.size()) {
            while (pos < src.size() &&
                   std::isspace(static_cast<unsigned char>(src[pos])))
                pos++;
            if (pos >= src.size() || src[pos] == '|') break;
            std::string tmp = nextWord(src, pos);
            if (tmp.empty()) break;
            names.temps.push_back(tmp);
        }
    }

    return names;
}

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

bool EggDebugSession::ensureTrace(size_t maxFrames) const {
    if (cachedTrace)
        return true;

    auto process = debugger->getProcess();
    if (!process) return false;

    auto mainThread = process->primaryThread();
    if (!mainThread) return false;

    cachedTrace = std::make_unique<smalldbg::StackTrace>(mainThread.get());
    if (cachedTrace->unwind(maxFrames) != smalldbg::Status::Ok) {
        cachedTrace.reset();
        return false;
    }
    return true;
}

bool EggDebugSession::resume() {
    cachedTrace.reset();
    return debugger->resume() == smalldbg::Status::Ok;
}

bool EggDebugSession::suspend() {
    cachedTrace.reset();
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
    cachedTrace.reset();
    return debugger->step() == smalldbg::Status::Ok;
}

bool EggDebugSession::stepOver() {
    cachedTrace.reset();
    // Step over: set a temporary breakpoint at the next instruction in the
    // current frame (i.e. the return address of the callee if stepping into
    // a call, or the very next instruction otherwise).  We approximate this
    // by setting a breakpoint at the caller's IP (frame 1) so that if the
    // current instruction is a call we stop when it returns.  Then resume.
    // If there's no caller frame we fall back to a plain single-step.
    auto thread = debugger->getCurrentThread();
    if (!thread) return step();

    smalldbg::StackTrace trace(thread.get());
    if (trace.unwind(2) != smalldbg::Status::Ok || trace.getFrameCount() < 2)
        return step();

    auto returnAddr = trace.getFrames()[1]->ip();
    debugger->setBreakpoint(returnAddr, "__stepover_tmp");
    bool ok = debugger->resume() == smalldbg::Status::Ok;
    if (ok) {
        debugger->waitForEvent(smalldbg::StopReason::None, -1);
    }
    debugger->clearBreakpoint(returnAddr);
    return ok;
}

bool EggDebugSession::stepOut() {
    cachedTrace.reset();
    // Step out: set a temporary breakpoint at the caller's return address
    // (frame 1 IP) and resume execution.
    auto thread = debugger->getCurrentThread();
    if (!thread) return false;

    smalldbg::StackTrace trace(thread.get());
    if (trace.unwind(2) != smalldbg::Status::Ok || trace.getFrameCount() < 2)
        return false;

    auto returnAddr = trace.getFrames()[1]->ip();
    debugger->setBreakpoint(returnAddr, "__stepout_tmp");
    bool ok = debugger->resume() == smalldbg::Status::Ok;
    if (ok) {
        debugger->waitForEvent(smalldbg::StopReason::None, -1);
    }
    debugger->clearBreakpoint(returnAddr);
    return ok;
}

bool EggDebugSession::stepBack() {
    cachedTrace.reset();
    return debugger->stepBack() == smalldbg::Status::Ok;
}

bool EggDebugSession::reverseStepOver() {
    cachedTrace.reset();
    // Reverse step over: step backwards, skipping over calls.
    // Use the caller's IP as a reverse breakpoint target.
    auto thread = debugger->getCurrentThread();
    if (!thread) return stepBack();

    smalldbg::StackTrace trace(thread.get());
    if (trace.unwind(2) != smalldbg::Status::Ok || trace.getFrameCount() < 2)
        return stepBack();

    auto returnAddr = trace.getFrames()[1]->ip();
    debugger->setBreakpoint(returnAddr, "__revstepover_tmp");
    bool ok = debugger->reverseResume() == smalldbg::Status::Ok;
    if (ok) {
        debugger->waitForEvent(smalldbg::StopReason::None, -1);
    }
    debugger->clearBreakpoint(returnAddr);
    return ok;
}

bool EggDebugSession::reverseStepOut() {
    cachedTrace.reset();
    // Reverse step out: run backwards until we re-enter the current frame.
    auto thread = debugger->getCurrentThread();
    if (!thread) return false;

    smalldbg::StackTrace trace(thread.get());
    if (trace.unwind(2) != smalldbg::Status::Ok || trace.getFrameCount() < 2)
        return false;

    auto returnAddr = trace.getFrames()[1]->ip();
    debugger->setBreakpoint(returnAddr, "__revstepout_tmp");
    bool ok = debugger->reverseResume() == smalldbg::Status::Ok;
    if (ok) {
        debugger->waitForEvent(smalldbg::StopReason::None, -1);
    }
    debugger->clearBreakpoint(returnAddr);
    return ok;
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
    if (!ensureTrace(maxFrames))
        return "[]";

    const auto& frames = cachedTrace->getFrames();
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
            .set("label", label)
            .set("ip", Json::hex(f.ip())));
    }
    return arr.dump();
}

// ---- C++ function source extraction from file ----

static bool readFileLines(const std::string& path,
                          std::vector<std::string>& out) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line))
        out.push_back(line);
    return !out.empty();
}

static int findOpeningBrace(const std::vector<std::string>& lines, int fromLine) {
    int depth = 0;
    for (int i = fromLine; i >= 0; i--) {
        const auto& s = lines[i];
        for (int j = static_cast<int>(s.size()) - 1; j >= 0; j--) {
            if (s[j] == '}') depth++;
            else if (s[j] == '{') {
                if (depth == 0) return i;
                depth--;
            }
        }
    }
    return -1;
}

static int findSignatureStart(const std::vector<std::string>& lines,
                              int openBraceLine) {
    int start = openBraceLine;
    for (int i = openBraceLine - 1; i >= 0; i--) {
        const auto& s = lines[i];
        if (s.empty()) break;
        char first = 0;
        for (char c : s) {
            if (c != ' ' && c != '\t') { first = c; break; }
        }
        if (first == '}' || first == '#' || first == 0) break;
        start = i;
    }
    return start;
}

static int findClosingBrace(const std::vector<std::string>& lines,
                            int openBraceLine) {
    int depth = 0;
    for (int i = openBraceLine; i < static_cast<int>(lines.size()); i++) {
        for (char c : lines[i]) {
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
    }
    return -1;
}

struct ExtractedSource {
    std::string text;
    int ipOffset{0};  // character offset of the IP line within text
    int ipLength{0};  // length of the IP line
};

static ExtractedSource extractFunctionSource(const std::string& filePath,
                                             uint32_t ipLine) {
    ExtractedSource result;
    std::vector<std::string> lines;
    if (!readFileLines(filePath, lines)) return result;
    if (ipLine == 0 || ipLine > lines.size()) return result;

    int target = static_cast<int>(ipLine) - 1;
    int openLine = findOpeningBrace(lines, target);
    if (openLine < 0) return result;

    int sigStart = findSignatureStart(lines, openLine);
    int closeLine = findClosingBrace(lines, openLine);
    if (closeLine < 0) return result;

    int charOffset = 0;
    for (int i = sigStart; i <= closeLine; i++) {
        if (i > sigStart) result.text += '\n';
        if (i == target) {
            result.ipOffset = static_cast<int>(result.text.size());
            result.ipLength = static_cast<int>(lines[i].size());
        }
        result.text += lines[i];
    }
    return result;
}

std::string EggDebugSession::getFrameDetail(int index) const {
    if (!ensureTrace())
        return "{}";

    const auto& frames = cachedTrace->getFrames();
    if (index < 1 || index > static_cast<int>(frames.size()))
        return "{}";

    // Lazily resolve source location for this frame
    cachedTrace->resolveFrameDetails(index - 1, debugger.get());

    const auto& f = *frames[index - 1];
    std::string label;
    if (!f.moduleName.empty() && !f.functionName.empty())
        label = f.moduleName + "!" + f.functionName;
    else if (!f.functionName.empty())
        label = f.functionName;
    else
        label = "<unknown>";

    std::string modName = f.moduleName.empty() ? "<native>" : f.moduleName;

    std::string source;
    int intervalStart = 0;
    int intervalEnd = 0;

    if (!f.sourceFile.empty() && f.sourceLine > 0) {
        auto extracted = extractFunctionSource(f.sourceFile, f.sourceLine);
        if (!extracted.text.empty()) {
            source = extracted.text;
            intervalStart = extracted.ipOffset;
            intervalEnd = extracted.ipOffset + extracted.ipLength;
        } else {
            source = f.functionName + " (source file not accessible: "
                   + f.sourceFile + ":" + std::to_string(f.sourceLine) + ")";
        }
    } else {
        source = f.functionName + " (native code)";
    }

    auto j = Json::object()
        .set("index", index)
        .set("label", label)
        .set("ip", Json::hex(f.ip()))
        .set("functionAddress", Json::hex(f.ip() - f.functionOffset))
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
            .set("source", source)
            .set("author", "")
            .set("timestamp", "")
            .set("package", ""))
        .set("interval", Json::object()
            .set("start", intervalStart)
            .set("end", intervalEnd));

    return j.dump();
}

std::string EggDebugSession::getFrameBindings(int index) const {
    if (!ensureTrace())
        return "[]";

    const auto& frames = cachedTrace->getFrames();
    if (index < 1 || index > static_cast<int>(frames.size()))
        return "[]";

    // Lazily resolve locals for this frame
    cachedTrace->resolveFrameDetails(index - 1, debugger.get());

    const auto& f = *frames[index - 1];
    auto arr = Json::array();

    // Frame registers: IP, FP, SP
    arr.add(Json::object()
        .set("name", "IP")
        .set("value", Json::hex(f.ip())));
    arr.add(Json::object()
        .set("name", "FP")
        .set("value", Json::hex(f.fp())));
    arr.add(Json::object()
        .set("name", "SP")
        .set("value", Json::hex(f.sp())));

    // Local variables (from DWARF debug info)
    for (const auto& lv : f.localVariables) {
        // Skip compiler-generated internal variables (e.g. __begin1, __end1,
        // __range1 from range-based for loops)
        if (lv.name.size() >= 2 && lv.name[0] == '_' && lv.name[1] == '_')
            continue;
        auto binding = Json::object()
            .set("name", lv.name)
            .set("type", lv.typeName)
            .set("location", lv.getLocationString());
        auto val = lv.getValue();
        if (val.has_value())
            binding.set("value", Json::hex(val.value()));
        else
            binding.set("value", "?");
        arr.add(binding);
    }

    return arr.dump();
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
        .set("oop", Json::hex(f.receiver.oop()))
        .set("type", "special"));

    if (!f.method)
        return arr.dump();

    int argCount = f.method.argCount();
    int tempCount = f.method.tempCount();

    auto names = parseMethodHeader(f.method.sourceCode());

    // Arguments: _stack[bp + FRAME_TO_FIRST_ARG_DELTA + i - 1] (0-based)
    for (int i = 0; i < argCount && i < 20; i++) {
        uint64_t argVal = inspector->readStackSlot(gt.state,
            f.bp + FRAME_TO_FIRST_ARG_DELTA + i);
        std::string name = (i < static_cast<int>(names.args.size()))
            ? names.args[i]
            : "arg" + std::to_string(i + 1);
        arr.add(Json::object()
            .set("name", name)
            .set("value", inspector->describeRemoteObject(
                              inspector->objectAt(argVal)))
            .set("oop", Json::hex(argVal))
            .set("type", "argument"));
    }

    // Temporaries: _stack[bp - FRAME_TO_FIRST_TEMP_DELTA - i - 1] (0-based)
    for (int i = 0; i < tempCount && i < 20; i++) {
        uint64_t tempVal = inspector->readStackSlot(gt.state,
            f.bp - FRAME_TO_FIRST_TEMP_DELTA - i);
        std::string name = (i < static_cast<int>(names.temps.size()))
            ? names.temps[i]
            : "temp" + std::to_string(i + 1);
        arr.add(Json::object()
            .set("name", name)
            .set("value", inspector->describeRemoteObject(
                              inspector->objectAt(tempVal)))
            .set("oop", Json::hex(tempVal))
            .set("type", "temporary"));
    }

    return arr.dump();
}

} // namespace webside
