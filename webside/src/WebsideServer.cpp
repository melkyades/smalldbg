#include "WebsideServer.h"
#include "Json.h"
#include "VMInspector.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/Disassembler.h"
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace webside {

static std::string threadIdHex(uint64_t tid) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(tid));
    return buf;
}

static bool isKnownFrameSubRoute(const std::string& sub) {
    return sub.empty() || sub == "bindings" || sub == "registers";
}

static uint64_t param64(const HttpRequest& req, const char* key, uint64_t dflt = 0) {
    auto it = req.params.find(key);
    if (it == req.params.end()) return dflt;
    try { return std::stoull(it->second, nullptr, 0); } catch (...) { return dflt; }
}

WebsideServer::WebsideServer(Workspace& workspace, int port)
    : server(port), workspace(workspace) {}

static HttpResponse refusal(int code, const char* status, const char* message) {
    HttpResponse response;
    response.statusCode = code;
    response.statusMessage = status;
    response.body = Json::object().set("error", message).dump();
    return response;
}

// A refused handler still answers something shaped like the truth, an empty
// list or a zeroed read, which a client cannot tell from the real thing.
HttpResponse WebsideServer::answerOrRefuse(const HttpRequest& request,
                                           const HttpHandler& handler) const {
    if (!workspace.isConnected()
        && !sessionFree.count(request.method + " " + request.path))
        return refusal(503, "Service Unavailable", "nothing is open");

    smalldbg::clearEngineBusy();
    HttpResponse response = handler(request);
    if (!smalldbg::engineWasBusy()) return response;
    return refusal(409, "Conflict", "debuggee is running");
}

void WebsideServer::sessionFreeRoute(const std::string& method,
                                     const std::string& path,
                                     HttpHandler handler) {
    sessionFree.insert(method + " " + path);
    server.route(method, path, std::move(handler));
}

// On a replay, a thread that was not running at this position has no
// registers, so its stack is unknown rather than empty.
std::string WebsideServer::frameWarning(smalldbg::Thread& thread) const {
    smalldbg::Registers regs;
    if (session().debugger().getRegisters(&thread, regs) != smalldbg::Status::Ok)
        return "registers for this thread could not be read";
    if (regs.sp() == 0)
        return "this thread has no register context here; it was not running "
               "at this position";
    return {};
}

// A listing asks this once rather than once per thread, since answering it
// may walk every thread the target has.
smalldbg::ThreadId WebsideServer::vmThreadId() const {
    auto thread = session().vmThread();
    return thread ? thread->getThreadId() : 0;
}

void WebsideServer::warn(HttpResponse& res, const std::string& warning) {
    if (!warning.empty()) res.headers["X-Webside-Warning"] = warning;
}

std::string WebsideServer::runControlResult(bool success) const {
    smalldbg::clearEngineBusy();
    return Json::object().set("success", success).dump();
}

void WebsideServer::run() {
    setupBaseRoutes();
    setupRoutes();
    server.setHandlerWrapper([this](const HttpRequest& request,
                                    const HttpHandler& handler) {
        return answerOrRefuse(request, handler);
    });
    server.run();
}

std::string WebsideServer::version() const { return "0.1.0"; }

// ---- run control / session state / class browsing: delegate to the session ----
bool WebsideServer::resume() {
    onPreResume();
    return session().resume();
}

bool WebsideServer::suspend() {
    if (!session().suspend()) return false;
    session().discoverClasses();
    session().refreshGreenThreads();
    onPostSuspend();
    return true;
}

bool WebsideServer::isActive() const {
    return workspace.isConnected() && session().isActive();
}
std::string WebsideServer::stopReason() const { return session().getStopReason(); }
std::optional<int> WebsideServer::pid() const { return session().getPid(); }

std::string WebsideServer::classListData(const std::string& root, bool namesOnly) const {
    return session().listClasses(root, namesOnly);
}
std::string WebsideServer::classDetailData(const std::string& name) const { return session().getClass(name); }
std::string WebsideServer::searchData(const std::string& text, bool ignoreCase,
                                      const std::string& condition, const std::string& type) const {
    return session().search(text, ignoreCase, condition, type);
}
std::string WebsideServer::subclassesData(const std::string& name) const { return session().getSubclasses(name); }
std::string WebsideServer::superclassesData(const std::string& name) const { return session().getSuperclasses(name); }
std::string WebsideServer::variablesData(const std::string& name) const { return session().getVariables(name); }
std::string WebsideServer::instanceVariablesData(const std::string& name) const { return session().getInstanceVariables(name); }
std::string WebsideServer::classVariablesData(const std::string& name) const { return session().getClassVariables(name); }
std::string WebsideServer::categoriesData(const std::string& name) const { return session().getCategories(name); }
std::string WebsideServer::usedCategoriesData(const std::string& name) const { return session().getUsedCategories(name); }
std::string WebsideServer::selectorsData(const std::string& name) const { return session().getSelectors(name); }
std::string WebsideServer::methodsData(const std::string& name) const { return session().getMethods(name); }
std::string WebsideServer::methodDetailData(const std::string& className,
                                            const std::string& selector) const {
    return session().getMethod(className, selector);
}

// ---- frame API: resolve the current thread/frame, then let the session format ----

std::string WebsideServer::listFrames() const {
    // Unwinding a running target blocks in the engine until it stops, so
    // decline the way the engine would rather than answer an empty stack.
    if (!session().debugger().isStopped()) {
        smalldbg::markEngineBusy();
        return "[]";
    }
    auto thread = session().vmThread();
    if (!thread) return "[]";
    return session().listFrames(*thread);
}

std::string WebsideServer::getFrameDetail(int index) const {
    auto thread = session().vmThread();
    if (!thread) return "{}";
    auto* trace = thread->getStackTrace(256);
    if (!trace) return "{}";
    const auto& frames = trace->getFrames();
    if (index < 1 || index > static_cast<int>(frames.size())) return "{}";
    return session().getFrameDetail(*trace, *frames[index - 1], index);
}

std::string WebsideServer::getFrameBindings(int index) const {
    auto thread = session().vmThread();
    if (!thread) return "[]";
    auto* trace = thread->getStackTrace(256);
    if (!trace) return "[]";
    const auto& frames = trace->getFrames();
    if (index < 1 || index > static_cast<int>(frames.size())) return "[]";
    return session().getFrameBindings(*trace, *frames[index - 1], index);
}

std::string WebsideServer::getFrameRegisters(int index) const {
    auto thread = session().vmThread();
    if (!thread) return "[]";
    auto* trace = thread->getStackTrace(256);
    if (!trace) return "[]";
    const auto& frames = trace->getFrames();
    if (index < 1 || index > static_cast<int>(frames.size())) return "[]";
    return session().getFrameRegisters(*frames[index - 1]);
}

std::string WebsideServer::stackDescriptors(smalldbg::Thread& thread,
                                            int selectedIndex, uint64_t from,
                                            int slots) const {
    auto* trace = thread.getStackTrace(256);
    if (!trace) return "[]";
    return session().stackDescriptors(*trace, selectedIndex, from, slots);
}

// =========================================================================
// Native symbol data
// =========================================================================

static const char* symbolTypeString(smalldbg::SymbolType type) {
    switch (type) {
        case smalldbg::SymbolType::Function:  return "function";
        case smalldbg::SymbolType::Variable:  return "variable";
        case smalldbg::SymbolType::Parameter: return "parameter";
        case smalldbg::SymbolType::Type:      return "type";
        default:                              return "unknown";
    }
}

static Json symbolToJson(const smalldbg::Symbol& sym) {
    return Json::object()
        .set("name", sym.name)
        .set("address", Json::hex(sym.address))
        .set("size", static_cast<int64_t>(sym.size))
        .set("type", symbolTypeString(sym.type))
        .set("module", sym.moduleName);
}

// Returns the pattern to search for what a person typed. The symbol engine
// matches whole names, so text without a wildcard is looked for anywhere in a
// name.
static std::string symbolPattern(const std::string& filter) {
    if (filter.empty()) return "*";
    if (filter.find('*') != std::string::npos
        || filter.find('?') != std::string::npos)
        return filter;
    return "*" + filter + "*";
}

std::string WebsideServer::nativeSymbolsData(const std::string& filter) const {
    auto* provider = session().debugger().getSymbolProvider();
    auto symbols = provider->findSymbols(symbolPattern(filter));
    auto arr = Json::array();
    for (auto& sym : symbols)
        arr.add(symbolToJson(sym));
    return arr.dump();
}

std::string WebsideServer::nativeModulesData() const {
    auto* provider = session().debugger().getSymbolProvider();
    auto modules = provider->getModules();
    auto arr = Json::array();
    for (auto& mod : modules) {
        arr.add(Json::object()
            .set("path", mod.path)
            .set("name", mod.shortName)
            .set("loadAddress", Json::hex(mod.loadAddress))
            .set("endAddress", Json::hex(mod.endAddress))
            .set("symbolCount", static_cast<int64_t>(mod.symbolCount))
            .set("symbolType", mod.symbolType)
            .set("symbolFile", mod.symbolFile));
    }
    return arr.dump();
}

// POST /native-modules/<name>/symbols
HttpResponse WebsideServer::handleLoadModuleSymbols(const HttpRequest& req) {
    HttpResponse res;
    auto segments = splitPath(req.path);
    if (segments.size() < 2) {
        res.statusCode = 400;
        res.body = Json::object()
            .set("error", "expected /native-modules/<name>/symbols").dump();
        return res;
    }
    std::string name = segments[1];

    session().loadModuleSymbols(name);

    // A module counts as loaded only when a symbol file was found. Only those
    // are remembered, so that later sessions do not search again for files
    // that do not exist.
    auto* provider = session().debugger().getSymbolProvider();
    for (const auto& mod : provider->getModules()) {
        if (mod.shortName != name) continue;
        bool loaded = !mod.symbolFile.empty();
        if (loaded) workspace.rememberSymbolModule(name);
        res.body = Json::object()
            .set("name", mod.shortName)
            .set("symbolType", mod.symbolType)
            .set("symbolFile", mod.symbolFile)
            .set("loaded", loaded)
            .dump();
        return res;
    }
    res.statusCode = 404;
    res.body = Json::object().set("error", "no module named " + name).dump();
    return res;
}

std::string WebsideServer::nativeSymbolDetailData(const std::string& name) const {
    auto* provider = session().debugger().getSymbolProvider();
    auto sym = provider->getSymbolByName(name);
    if (!sym) return "{}";
    return symbolToJson(*sym).dump();
}

// ---- Expression parser for native struct traversal ----

struct PathStep {
    bool dereference; // true for ->, false for .
    std::string fieldName;
};

struct ParsedExpression {
    std::string rootSymbol;
    std::vector<PathStep> steps;
};

// Returns the name that starts at `pos`, up to the next '.' or '->', and moves
// `pos` to that separator.
static std::string readFieldName(const std::string& expr, size_t& pos) {
    size_t start = pos;
    while (pos < expr.size() && expr[pos] != '.' &&
           !(expr[pos] == '-' && pos + 1 < expr.size() && expr[pos + 1] == '>'))
        pos++;
    return expr.substr(start, pos - start);
}

static ParsedExpression parseNativeExpression(const std::string& expr) {
    ParsedExpression result;
    size_t pos = 0;

    // Find the first -> or . (these never appear in C++ qualified names)
    while (pos < expr.size()) {
        if (expr[pos] == '-' && pos + 1 < expr.size() && expr[pos + 1] == '>')
            break;
        if (expr[pos] == '.')
            break;
        pos++;
    }

    result.rootSymbol = expr.substr(0, pos);

    while (pos < expr.size()) {
        PathStep step;
        if (expr[pos] == '-' && pos + 1 < expr.size() && expr[pos + 1] == '>') {
            step.dereference = true;
            pos += 2;
        } else if (expr[pos] == '.') {
            step.dereference = false;
            pos += 1;
        } else {
            break;
        }

        step.fieldName = readFieldName(expr, pos);
        result.steps.push_back(std::move(step));
    }

    return result;
}

static const char* typeKindString(smalldbg::NativeTypeKind kind) {
    switch (kind) {
    case smalldbg::NativeTypeKind::Void:      return "void";
    case smalldbg::NativeTypeKind::Bool:      return "bool";
    case smalldbg::NativeTypeKind::Int:       return "int";
    case smalldbg::NativeTypeKind::UInt:      return "uint";
    case smalldbg::NativeTypeKind::Float:     return "float";
    case smalldbg::NativeTypeKind::Char:      return "char";
    case smalldbg::NativeTypeKind::Pointer:   return "pointer";
    case smalldbg::NativeTypeKind::Reference: return "reference";
    case smalldbg::NativeTypeKind::Struct:    return "struct";
    case smalldbg::NativeTypeKind::Class:     return "class";
    case smalldbg::NativeTypeKind::Union:     return "union";
    case smalldbg::NativeTypeKind::Enum:      return "enum";
    case smalldbg::NativeTypeKind::Array:     return "array";
    case smalldbg::NativeTypeKind::Typedef:   return "typedef";
    case smalldbg::NativeTypeKind::Const:     return "const";
    case smalldbg::NativeTypeKind::Volatile:  return "volatile";
    default:                                   return "unknown";
    }
}

static Json fieldsToJson(const std::vector<smalldbg::NativeField>& fields) {
    auto arr = Json::array();
    for (auto& f : fields) {
        arr.add(Json::object()
            .set("name", f.name)
            .set("type", f.typeName)
            .set("kind", typeKindString(f.typeKind))
            .set("offset", static_cast<int64_t>(f.offset))
            .set("size", static_cast<int64_t>(f.size)));
    }
    return arr;
}

// Returns the field of `info` named `name`, or null when it has none.
static const smalldbg::NativeField* fieldNamed(const smalldbg::NativeTypeInfo& info,
                                               const std::string& name) {
    for (const auto& field : info.fields)
        if (field.name == name) return &field;
    return nullptr;
}

/** Follows `steps` from `address`, which holds a `typeName`, reading a pointer
 *  wherever a step dereferences one. Sets the address, type and size of the
 *  field reached. Returns false when a step names no field of its struct or a
 *  pointer cannot be read. **/
static bool followPath(const std::vector<PathStep>& steps,
                       smalldbg::Debugger& debugger,
                       uint64_t& address, std::string& typeName,
                       uint64_t& size) {
    auto& provider = *debugger.getSymbolProvider();
    for (const auto& step : steps) {
        if (step.dereference) {
            uint64_t pointer = 0;
            if (debugger.readMemory(address, &pointer,
                                    debugger.arch()->pointerSize())
                != smalldbg::Status::Ok)
                return false;
            address = pointer;
        }

        auto* structInfo = provider.getStructType(typeName);
        if (!structInfo) return false;

        const smalldbg::NativeField* field = fieldNamed(*structInfo, step.fieldName);
        if (!field) return false;

        address += field->offset;
        typeName = field->typeName;
        // The struct says how wide its own member is. Looking the member's
        // type up by name would ask the engine about "unsigned int*", which
        // belongs to no module and reads back as eight bytes on a 32-bit
        // target.
        size = field->size;
    }
    return true;
}

std::string WebsideServer::nativeInspectData(const std::string& expression) const {
    auto& debugger = session().debugger();
    auto* provider = debugger.getSymbolProvider();

    auto parsed = parseNativeExpression(expression);
    if (parsed.rootSymbol.empty()) return "{}";

    auto rootSym = provider->getSymbolByName(parsed.rootSymbol);
    if (!rootSym) return "{}";

    auto rootTypeName = provider->getVariableTypeName(parsed.rootSymbol);
    if (!rootTypeName) return "{}";

    uint64_t currentAddr = rootSym->address;
    std::string currentTypeName = *rootTypeName;
    uint64_t fieldSize = 0;
    if (!followPath(parsed.steps, debugger, currentAddr, currentTypeName,
                    fieldSize))
        return "{}";

    // A field's own size is the one to trust; see followPath.
    auto* typeInfo = provider->getTypeByName(currentTypeName);
    uint64_t size = fieldSize ? fieldSize : typeInfo ? typeInfo->size : 0;
    size_t readSize = size > 0 && size <= 8 ? static_cast<size_t>(size)
                                            : debugger.arch()->pointerSize();
    uint64_t rawValue = 0;
    debugger.readMemory(currentAddr, &rawValue, readSize);

    std::vector<smalldbg::NativeField> visibleFields;
    auto* structInfo = provider->getStructType(currentTypeName);
    if (structInfo)
        visibleFields = structInfo->fields;

    auto result = Json::object()
        .set("expression", expression)
        .set("address", Json::hex(currentAddr))
        .set("value", Json::hex(rawValue))
        .set("type", currentTypeName)
        .set("kind", typeKindString(typeInfo ? typeInfo->kind : smalldbg::NativeTypeKind::Unknown))
        .set("size", static_cast<int64_t>(size))
        .set("fields", fieldsToJson(visibleFields));

    return result.dump();
}

// =========================================================================
// VM inspector routes: what is VM-specific comes from the session's inspector
// =========================================================================

static Json moduleToCodeZone(const smalldbg::ModuleInfo& mod) {
    return Json::object()
        .set("start", Json::hex(mod.loadAddress))
        .set("end", Json::hex(mod.endAddress))
        .set("size", static_cast<int64_t>(mod.endAddress - mod.loadAddress));
}

HttpResponse WebsideServer::handleRegions(const HttpRequest&) const {
    HttpResponse res;
    auto* inspector = &session().inspector();
    if (!isActive() || !inspector) { res.body = "{}"; return res; }

    auto* provider = session().debugger().getSymbolProvider();
    auto result = Json::object();

    auto codeZones = Json::object();
    auto modules = provider->getModules();
    for (auto& mod : modules)
        codeZones.set(mod.shortName, moduleToCodeZone(mod));
    result.set("codeZones", codeZones);

    auto stack = inspector->evaluatorStack();
    if (stack.valid) {
        result.set("stack", Json::object()
            .set("base", Json::hex(stack.base))
            .set("sp", Json::hex(stack.sp))
            .set("bp", Json::hex(stack.bp)));
    } else {
        result.set("stack", Json::null());
    }

    auto moduleList = Json::array();
    for (auto& mod : modules) {
        moduleList.add(Json::object()
            .set("name", mod.shortName)
            .set("path", mod.path)
            .set("start", Json::hex(mod.loadAddress))
            .set("end", Json::hex(mod.endAddress)));
    }
    result.set("modules", moduleList);

    res.body = result.dump();
    return res;
}

HttpResponse WebsideServer::handleClassify(const HttpRequest& req) const {
    HttpResponse res;
    auto* inspector = &session().inspector();
    if (!isActive() || !inspector) { res.body = "{}"; return res; }

    auto addrIt = req.params.find("address");
    if (addrIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(addrIt->second);
    auto* provider = session().debugger().getSymbolProvider();

    auto result = Json::object();
    result.set("address", Json::hex(addr));

    std::string moduleName;
    auto modules = provider->getModules();
    for (auto& mod : modules) {
        if (addr >= mod.loadAddress && addr < mod.endAddress) {
            moduleName = mod.shortName;
            break;
        }
    }
    result.set("module", moduleName.empty() ? Json::null() : Json::string(moduleName));

    auto stack = inspector->evaluatorStack();
    bool inStack = false;
    if (stack.valid && stack.base != 0 && stack.sp > 0) {
        uint64_t stackStart = stack.base;
        uint64_t stackEnd = stack.base + stack.sp * 8;
        inStack = (addr >= stackStart && addr < stackEnd);
    }
    result.set("stack", inStack);

    auto sym = provider->getSymbolByAddress(addr);
    if (sym) {
        result.set("symbol", sym->name);
        result.set("offset", static_cast<int64_t>(addr - sym->address));
    } else {
        result.set("symbol", nullptr);
        result.set("offset", nullptr);
    }

    result.set("space", nullptr);
    result.set("codeZone", moduleName.empty() ? Json::null() : Json::string(moduleName));

    res.body = result.dump();
    return res;
}

std::string WebsideServer::inspectJson(uint64_t, int) const { return "{}"; }

HttpResponse WebsideServer::handleInspect(const HttpRequest& req) const {
    HttpResponse res;
    auto* inspector = &session().inspector();
    if (!isActive() || !inspector) { res.body = "{}"; return res; }

    auto oopIt = req.params.find("oop");
    if (oopIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing oop parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(oopIt->second);
    int maxSlots = 20;
    auto maxIt = req.params.find("maxSlots");
    if (maxIt != req.params.end()) {
        try { maxSlots = std::stoi(maxIt->second); } catch (...) {}
    }

    res.body = inspectJson(addr, maxSlots);
    return res;
}

// =========================================================================
// /debuggers routes
// =========================================================================

// Primary first, so the id a client remembers stays the main thread.
std::vector<std::shared_ptr<smalldbg::Thread>>
WebsideServer::nativeThreads() const {
    auto* dbg = &session().debugger();
    if (!dbg) return {};
    auto proc = dbg->getProcess();
    if (!proc) return {};

    auto primary = session().vmThread();
    std::vector<std::shared_ptr<smalldbg::Thread>> ordered;
    if (primary) ordered.push_back(primary);
    for (auto& t : proc->threads()) {
        if (!t) continue;
        if (!primary || t->getThreadId() != primary->getThreadId())
            ordered.push_back(t);
    }
    return ordered;
}

HttpResponse WebsideServer::handleDebuggerRoute(const HttpRequest& req) const {
    HttpResponse res;
    auto segments = splitPath(req.path);
    // segments: ["debuggers", "<id>", ...]
    if (segments.size() < 2) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing debugger id").dump();
        return res;
    }

    int debuggerId = 0;
    try { debuggerId = std::stoi(segments[1]); } catch (...) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Invalid debugger id").dump();
        return res;
    }

    if (!isActive()) {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Debugger not active").dump();
        return res;
    }

    // Native OS threads are 1..N; green threads are N+1..N+M.
    auto threads = nativeThreads();
    int nativeCount = static_cast<int>(threads.size());
    if (debuggerId >= 1 && debuggerId <= nativeCount)
        return handleNativeDebuggerRoute(segments, req, *threads[debuggerId - 1], debuggerId);

    int threadIndex = debuggerId - nativeCount - 1;  // 0-based green index
    if (threadIndex < 0 || threadIndex >= session().greenThreadCount()) {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Debugger not found").dump();
        return res;
    }

    // A green thread that is running has its current frames on the OS thread
    // running it; what the VM saved for it is from when it last stopped.
    if (segments.size() > 2) {
        uint64_t runner = session().nativeThreadOf(threadIndex);
        for (int i = 0; runner != 0 && i < nativeCount; i++)
            if (threads[i]->getThreadId() == runner)
                return handleNativeDebuggerRoute(segments, req, *threads[i], i + 1);
    }

    return handleSmalltalkDebuggerRoute(segments, req, threadIndex, debuggerId);
}

HttpResponse WebsideServer::handleNativeDebuggerRoute(
    const std::vector<std::string>& segments, const HttpRequest& req,
    smalldbg::Thread& thread, int debuggerId) const {
    HttpResponse res;

    if (segments.size() == 2) {
        res.body = Json::object()
            .set("id", debuggerId)
            .set("description", "Native thread " + threadIdHex(thread.getThreadId())
                              + (thread.getThreadId() == vmThreadId() ? " (main)" : ""))
            .set("status", stopReason())
            .dump();
        return res;
    }

    if (segments[2] == "stack") {
        res.body = stackDescriptors(thread,
                                    static_cast<int>(param64(req, "frame", 1)),
                                    param64(req, "address"),
                                    static_cast<int>(param64(req, "count", 64)));
        return res;
    }

    if (segments[2] == "frames") {
        if (segments.size() == 3) {
            res.body = session().listFrames(thread);
            warn(res, frameWarning(thread));
            return res;
        }
        std::string sub = segments.size() > 4 ? segments[4] : "";
        if (!isKnownFrameSubRoute(sub)) {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Unknown sub-route").dump();
            return res;
        }
        int index = 0;
        try { index = std::stoi(segments[3]); } catch (...) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Invalid frame index").dump();
            return res;
        }
        auto* trace = thread.getStackTrace(256);
        if (!trace) {
            res.body = sub.empty() ? "{}" : "[]";
            return res;
        }
        const auto& frames = trace->getFrames();
        if (index < 1 || index > static_cast<int>(frames.size())) {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Frame not found").dump();
            return res;
        }
        if (sub == "bindings")
            res.body = session().getFrameBindings(*trace, *frames[index - 1], index);
        else if (sub == "registers")
            res.body = session().getFrameRegisters(*frames[index - 1]);
        else
            res.body = session().getFrameDetail(*trace, *frames[index - 1], index);
        return res;
    }

    res.statusCode = 404;
    res.body = Json::object().set("error", "Unknown sub-route").dump();
    return res;
}

HttpResponse WebsideServer::handleSmalltalkDebuggerRoute(
    const std::vector<std::string>& segments, const HttpRequest& req,
    int threadIndex, int debuggerId) const {
    HttpResponse res;

    if (segments.size() == 2) {
        res.body = Json::object()
            .set("id", debuggerId)
            .set("description", "Smalltalk: " +
                session().getGreenThreadName(threadIndex))
            .set("status", stopReason())
            .dump();
        return res;
    }

    if (segments[2] == "stack") {
        res.body = session().getSmalltalkStackContents(
            threadIndex, static_cast<int>(param64(req, "frame", 1)));
        return res;
    }

    if (segments[2] == "frames") {
        if (segments.size() == 3) {
            res.body = session().listSmalltalkFrames(threadIndex);
            return res;
        }
        int index = 0;
        try { index = std::stoi(segments[3]); } catch (...) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Invalid frame index").dump();
            return res;
        }
        std::string sub = segments.size() > 4 ? segments[4] : "";
        if (sub == "bindings") {
            res.body = session().getSmalltalkFrameBindings(threadIndex, index);
        } else if (sub == "registers") {
            res.body = session().getSmalltalkFrameRegisters(threadIndex, index);
        } else if (!sub.empty()) {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Unknown sub-route").dump();
        } else {
            res.body = session().getSmalltalkFrameDetail(threadIndex, index);
            if (res.body == "{}") {
                res.statusCode = 404;
                res.body = Json::object().set("error", "Frame not found").dump();
            }
        }
        return res;
    }

    res.statusCode = 404;
    res.body = Json::object().set("error", "Unknown sub-route").dump();
    return res;
}

// =========================================================================
// Memory / disassembly
// =========================================================================

uint64_t WebsideServer::parseHexParam(const std::string& s) {
    if (s.empty()) return 0;
    try {
        return std::stoull(s, nullptr, 0);
    } catch (...) {
        return 0;
    }
}

static size_t typeUnitSize(const std::string& type) {
    if (type == "uint16" || type == "int16") return 2;
    if (type == "uint32" || type == "int32") return 4;
    if (type == "uint64" || type == "int64") return 8;
    return 1;
}

static uint64_t rawUnit(const uint8_t* unit, size_t unitSize) {
    switch (unitSize) {
    case 2: return *reinterpret_cast<const uint16_t*>(unit);
    case 4: return *reinterpret_cast<const uint32_t*>(unit);
    case 8: return *reinterpret_cast<const uint64_t*>(unit);
    }
    return *unit;
}

static int64_t readTypedValue(const uint8_t* buf, size_t unitSize, bool isSigned) {
    uint64_t raw = rawUnit(buf, unitSize);
    if (isSigned) {
        switch (unitSize) {
        case 1: return static_cast<int8_t>(raw);
        case 2: return static_cast<int16_t>(raw);
        case 4: return static_cast<int32_t>(raw);
        case 8: return static_cast<int64_t>(raw);
        }
    }
    return static_cast<int64_t>(raw);
}

static std::string formatHexDump(const std::vector<uint8_t>& buf) {
    std::string hex;
    for (size_t i = 0; i < buf.size(); i++) {
        if (i > 0) hex += ' ';
        char h[4];
        snprintf(h, sizeof(h), "%02X", buf[i]);
        hex += h;
    }
    return hex;
}

static std::string formatAsciiDump(const std::vector<uint8_t>& buf) {
    std::string ascii;
    for (uint8_t b : buf)
        ascii += (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
    return ascii;
}

bool WebsideServer::readByteDump(uint64_t address, int count,
                                 Json& result) const {
    std::vector<uint8_t> buf(count);
    if (session().debugger().readMemory(address, buf.data(), count)
        != smalldbg::Status::Ok)
        return false;
    result.set("hex", formatHexDump(buf));
    result.set("ascii", formatAsciiDump(buf));
    result.set("size", count);
    return true;
}

bool WebsideServer::readStringAt(uint64_t address, int count,
                                 Json& result) const {
    std::vector<uint8_t> buf(count);
    if (session().debugger().readMemory(address, buf.data(), count)
        != smalldbg::Status::Ok)
        return false;
    std::string text;
    for (int i = 0; i < count && buf[i] != 0; i++)
        text += static_cast<char>(buf[i]);
    result.set("type", "string");
    result.set("value", text);
    result.set("size", static_cast<int64_t>(text.size()));
    return true;
}

bool WebsideServer::readTypedUnits(uint64_t address, int count,
                                   const std::string& type, bool asHex,
                                   Json& result) const {
    size_t unitSize = typeUnitSize(type);
    bool isSigned = !type.empty() && type[0] == 'i';
    size_t totalBytes = std::min(unitSize * count, static_cast<size_t>(32768));

    std::vector<uint8_t> buf(totalBytes, 0);
    if (session().debugger().readMemory(address, buf.data(), totalBytes)
        != smalldbg::Status::Ok)
        return false;

    auto values = Json::array();
    int unitCount = static_cast<int>(totalBytes / unitSize);
    for (int i = 0; i < unitCount; i++)
        values.add(unitJson(buf.data() + i * unitSize, unitSize, isSigned,
                            asHex));

    result.set("type", type);
    result.set("values", values);
    return true;
}

Json WebsideServer::unitJson(const uint8_t* unit, size_t unitSize,
                             bool isSigned, bool asHex) {
    if (!asHex) return Json::number(readTypedValue(unit, unitSize, isSigned));
    uint64_t raw = rawUnit(unit, unitSize);
    return unitSize <= 4 ? Json::hex(static_cast<uint32_t>(raw)) : Json::hex(raw);
}

HttpResponse WebsideServer::handleMemory(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto addrIt = req.params.find("address");
    if (addrIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(addrIt->second);

    std::string type = "bytes";
    auto typeIt = req.params.find("type");
    if (typeIt != req.params.end()) type = typeIt->second;

    int count = 256;
    auto countIt = req.params.find("count");
    if (countIt != req.params.end()) {
        try { count = std::stoi(countIt->second); } catch (...) {}
    }
    count = std::clamp(count, 1, 4096);

    auto result = Json::object();
    result.set("address", Json::hex(addr));

    bool read = false;
    if (type == "bytes") {
        read = readByteDump(addr, count, result);
    } else if (type == "string") {
        read = readStringAt(addr, count, result);
    } else {
        auto formatIt = req.params.find("format");
        bool asHex = formatIt != req.params.end() && formatIt->second == "hex";
        read = readTypedUnits(addr, count, type, asHex, result);
    }
    if (!read) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Failed to read memory").dump();
        return res;
    }

    res.body = result.dump();
    return res;
}

HttpResponse WebsideServer::handleDisassemble(const HttpRequest& req) {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto addrIt = req.params.find("address");
    if (addrIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(addrIt->second);

    int byteCount = 64;
    auto countIt = req.params.find("count");
    if (countIt != req.params.end()) {
        try { byteCount = std::stoi(countIt->second); } catch (...) {}
    }
    byteCount = std::clamp(byteCount, 1, 4096);

    auto process = session().debugger().getProcess();
    std::vector<uint8_t> buf(byteCount);
    if (process->readMemory(addr, buf.data(), byteCount) != smalldbg::Status::Ok) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Failed to read memory").dump();
        return res;
    }

    smalldbg::Disassembler* dis = session().debugger().getDisassembler();
    auto insns = dis->disassemble(buf.data(), buf.size(), addr);

    auto instructions = Json::array();
    for (const auto& ins : insns) {
        instructions.add(Json::object()
            .set("address", Json::hex(ins.address))
            .set("size", ins.size)
            .set("bytes", ins.bytes)
            .set("text", ins.text));
    }

    auto result = Json::object()
        .set("address", Json::hex(addr))
        .set("size", byteCount)
        .set("hex", formatHexDump(buf))
        .set("instructions", instructions);

    res.body = result.dump();
    return res;
}

HttpResponse WebsideServer::handleSymbol(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto nameIt = req.params.find("name");
    if (nameIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing name parameter").dump();
        return res;
    }

    auto* provider = session().debugger().getSymbolProvider();
    auto sym = provider->getSymbolByName(nameIt->second);
    if (!sym) {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Symbol not found").dump();
        return res;
    }

    auto result = symbolToJson(*sym);

    // A pointer-sized read: on a 32-bit target the next four bytes belong to
    // whatever follows the symbol.
    uint64_t value = 0;
    auto process = session().debugger().getProcess();
    if (process->readMemory(sym->address, &value, session().pointerSize())
        == smalldbg::Status::Ok)
        result.set("value", session().addressHex(value));
    else
        result.set("value", nullptr);

    res.body = result.dump();
    return res;
}

void WebsideServer::setupRoutes() {
    // ---- Search ----
    server.route("GET", "/search", [this](const HttpRequest& req) {
        HttpResponse res;
        std::string text;
        bool ignoreCase = false;
        std::string condition = "beginning";
        std::string type = "all";

        auto it = req.params.find("text");
        if (it != req.params.end()) text = it->second;
        it = req.params.find("ignoreCase");
        if (it != req.params.end()) ignoreCase = (it->second == "true" || it->second == "1");
        it = req.params.find("condition");
        if (it != req.params.end()) condition = it->second;
        it = req.params.find("type");
        if (it != req.params.end()) type = it->second;

        res.body = searchData(text, ignoreCase, condition, type);
        return res;
    });

    // ---- Classes — exact match for the listing ----
    server.route("GET", "/classes", [this](const HttpRequest& req) {
        return handleClassList(req);
    });

    // ---- Classes — prefix routes for detail / sub-routes ----
    server.routePrefix("GET", "/classes", [this](const HttpRequest& req) {
        return handleClassesPrefix(req);
    });

    setupSymbolRoutes();
    setupInspectorRoutes();
    setupDebuggerRoutes();
}

// Symbols, modules, memory and disassembly: what the target looks like
// as a native program.
void WebsideServer::setupSymbolRoutes() {
    // ---- Native symbols ----
    server.route("GET", "/native-symbols", [this](const HttpRequest& req) {
        HttpResponse res;
        std::string filter;
        auto it = req.params.find("filter");
        if (it != req.params.end()) filter = it->second;
        res.body = nativeSymbolsData(filter);
        return res;
    });

    server.routePrefix("GET", "/native-symbols", [this](const HttpRequest& req) {
        HttpResponse res;
        auto segments = splitPath(req.path);
        if (segments.size() < 2) {
            res.body = nativeSymbolsData("");
            return res;
        }
        // /native-symbols/<name>
        std::string name;
        for (size_t i = 1; i < segments.size(); i++) {
            if (i > 1) name += "/";
            name += segments[i];
        }
        res.body = nativeSymbolDetailData(name);
        if (res.body == "{}") {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Symbol not found").dump();
        }
        return res;
    });

    server.route("GET", "/native-modules", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = nativeModulesData();
        return res;
    });

    // A module's symbols load when they are first needed; this loads them now.
    server.routePrefix("POST", "/native-modules", [this](const HttpRequest& req) {
        return handleLoadModuleSymbols(req);
    });

    server.route("GET", "/symbol", [this](const HttpRequest& req) {
        return handleSymbol(req);
    });

    server.route("GET", "/memory", [this](const HttpRequest& req) {
        return handleMemory(req);
    });

    server.route("GET", "/disassemble", [this](const HttpRequest& req) {
        return handleDisassemble(req);
    });

    server.route("GET", "/native-inspect", [this](const HttpRequest& req) {
        HttpResponse res;
        std::string expression;
        auto it = req.params.find("expression");
        if (it != req.params.end()) expression = it->second;
        if (expression.empty()) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Missing 'expression' parameter").dump();
            return res;
        }
        res.body = nativeInspectData(expression);
        if (res.body == "{}") {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Cannot resolve expression").dump();
        }
        return res;
    });
}

// The VM's own view of its memory: spaces, what an address is, what an
// object holds.
void WebsideServer::setupInspectorRoutes() {
    // ---- VM inspector ----
    server.route("GET", "/regions", [this](const HttpRequest& req) {
        return handleRegions(req);
    });
    server.route("GET", "/classify", [this](const HttpRequest& req) {
        return handleClassify(req);
    });
    server.route("GET", "/inspect", [this](const HttpRequest& req) {
        return handleInspect(req);
    });

}

// The green threads are listed first, as the program a Smalltalk developer
// came to look at. Ids still count the native threads first.
std::string WebsideServer::debuggerListJson() const {
    auto array = Json::array();
    auto threads = nativeThreads();
    addGreenThreadDebuggers(array, static_cast<int>(threads.size()) + 1);
    const smalldbg::ThreadId main = vmThreadId();
    int id = 1;
    for (size_t i = 0; i < threads.size(); i++, id++) {
        array.add(Json::object()
            .set("id", id)
            .set("description", "Native thread " + threadIdHex(threads[i]->getThreadId())
                              + (threads[i]->getThreadId() == main ? " (main)" : ""))
            .set("status", stopReason()));
    }
    return array.dump();
}

void WebsideServer::addGreenThreadDebuggers(Json& array, int id) const {
    const int count = session().greenThreadCount();
    for (int i = 0; i < count; i++, id++) {
        array.add(Json::object()
            .set("id", id)
            .set("description", "Smalltalk: " + session().getGreenThreadName(i))
            .set("status", stopReason()));
    }
}

std::string WebsideServer::threadListJson() const {
    auto array = Json::array();
    auto threads = nativeThreads();
    addGreenThreads(array, static_cast<int>(threads.size()) + 1);
    const smalldbg::ThreadId main = vmThreadId();
    int id = 1;
    for (size_t i = 0; i < threads.size(); i++, id++) {
        Json entry = nativeThreadJson(*threads[i], id, main);
        if (!entry.isNull()) array.add(std::move(entry));
    }
    return array.dump();
}

Json WebsideServer::nativeThreadJson(smalldbg::Thread& thread, int id,
                                     smalldbg::ThreadId main) const {
    auto* debugger = &session().debugger();
    const bool stopped = debugger->isStopped();
    smalldbg::ThreadIdentity identity = stopped
        ? debugger->threadIdentity(thread) : smalldbg::ThreadIdentity{};
    if (stopped && !identity.hasContext) return Json::null();

    auto current = debugger->getCurrentThread();

    auto entry = Json::object()
        .set("debuggerId", id)
        .set("id", threadIdHex(thread.getThreadId()))
        .set("type", "native")
        .set("name", identity.name)
        .set("isMain", thread.getThreadId() == main)
        .set("isCurrent", current && current->getThreadId() == thread.getThreadId())
        .set("status", stopReason());

    std::string green = stopped ? session().greenThreadOn(thread.getThreadId())
                                : std::string();
    if (!green.empty()) entry.set("runs", green);
    return entry;
}

void WebsideServer::addGreenThreads(Json& array, int id) const {
    const int count = session().greenThreadCount();
    for (int i = 0; i < count; i++, id++) {
        array.add(Json::object()
            .set("debuggerId", id)
            .set("id", std::to_string(i + 1))
            .set("type", "smalltalk")
            .set("name", session().getGreenThreadName(i))
            .set("isMain", false)
            .set("isCurrent", false)
            .set("terminated", !session().isGreenThreadLive(i))
            .set("status", stopReason()));
    }
}

// Threads and the frames on them, plus the run control that moves them.
void WebsideServer::setupDebuggerRoutes() {
    // ---- Debuggers: native OS threads 1..N (primary first), green threads N+1.. ----
    server.route("GET", "/debuggers", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = isActive() ? debuggerListJson() : "[]";
        return res;
    });

    // ---- Threads: native OS threads (+ green threads); debuggerId maps to /debuggers/<id> ----
    server.route("GET", "/threads", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = isActive() ? threadListJson() : "[]";
        return res;
    });

    server.routePrefix("GET", "/debuggers", [this](const HttpRequest& req) {
        return handleDebuggerRoute(req);
    });

    setupDebuggerActionRoutes();
}

bool WebsideServer::stepAction(const std::vector<std::string>& segments) {
    int debuggerId = 0;
    try { debuggerId = std::stoi(segments[1]); } catch (...) {}
    auto threads = nativeThreads();
    if (debuggerId >= 1 && debuggerId <= static_cast<int>(threads.size()))
        session().debugger().setCurrentThread(threads[debuggerId - 1]);

    const std::string& action = segments[4];
    if (action == "stepinto")          return session().step();
    if (action == "stepover")          return session().stepOver();
    if (action == "stepout")           return session().stepOut();
    if (action == "reversestepinto")   return session().stepBack();
    if (action == "reversestepover")   return session().reverseStepOver();
    if (action == "reversestepout")    return session().reverseStepOut();
    return false;
}

HttpResponse WebsideServer::handleRunTo(const HttpRequest& req, bool backwards) {
    HttpResponse res;
    auto segments = splitPath(req.path);
    int debuggerId = 0;
    try { debuggerId = std::stoi(segments[1]); } catch (...) {}
    auto threads = nativeThreads();
    if (debuggerId >= 1 && debuggerId <= static_cast<int>(threads.size()))
        session().debugger().setCurrentThread(threads[debuggerId - 1]);

    auto body = Json::parse(req.body);
    uint64_t address = 0;
    if (body["address"].isNumber()) address = body["address"].asUInt();
    else address = parseHexParam(body["address"].asString());
    if (address == 0) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "address required").dump();
        return res;
    }

    bool reached = backwards ? session().reverseRunToAddress(address)
                             : session().runToAddress(address);
    res.body = runControlResult(reached);
    return res;
}

// Run control aimed at one debugger id: resume, suspend, terminate, run to an
// address, and the steps.
void WebsideServer::setupDebuggerActionRoutes() {
    server.routePrefix("POST", "/debuggers", [this](const HttpRequest& req) {
        HttpResponse res;
        auto segments = splitPath(req.path);

        if (segments.size() >= 3 && segments[2] == "resume") {
            res.body = runControlResult(resume());
            return res;
        }

        if (segments.size() >= 3 && segments[2] == "suspend") {
            res.body = runControlResult(suspend());
            return res;
        }

        if (segments.size() >= 3 && segments[2] == "terminate") {
            workspace.close();
            res.body = Json::object().set("success", true).dump();
            return res;
        }

        if (segments.size() >= 3 && segments[2] == "runto")
            return handleRunTo(req, false);

        if (segments.size() >= 3 && segments[2] == "reverserunto")
            return handleRunTo(req, true);

        if (segments.size() >= 5 && segments[2] == "frames") {
            res.body = runControlResult(stepAction(segments));
            return res;
        }

        res.statusCode = 404;
        res.body = Json::object().set("error", "unknown debugger action").dump();
        return res;
    });
}

// =========================================================================
// Class name parsing
// =========================================================================

WebsideServer::ClassIdent WebsideServer::parseClassName(const std::string& name) {
    ClassIdent id;
    id.className = name;
    const std::string suffix = " class";
    if (name.size() > suffix.size() &&
        name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
        id.isMetaclass = true;
        id.baseName = name.substr(0, name.size() - suffix.size());
    } else {
        id.isMetaclass = false;
        id.baseName = name;
    }
    return id;
}

// =========================================================================
// /classes — list
// =========================================================================

HttpResponse WebsideServer::handleClassList(const HttpRequest& req) const {
    HttpResponse res;
    std::string root;
    bool namesOnly = false;

    auto it = req.params.find("root");
    if (it != req.params.end()) root = it->second;
    it = req.params.find("names");
    if (it != req.params.end()) namesOnly = (it->second == "true" || it->second == "1");

    res.body = classListData(root, namesOnly);
    return res;
}

// =========================================================================
// /classes/{name} — detail
// =========================================================================

HttpResponse WebsideServer::handleClassDetail(const std::string& className) const {
    HttpResponse res;
    res.body = classDetailData(className);
    if (res.body == "{}") {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Class not found").dump();
    }
    return res;
}

// =========================================================================
// /classes/* — prefix dispatcher
// =========================================================================

HttpResponse WebsideServer::handleClassesPrefix(const HttpRequest& req) const {
    HttpResponse res;
    auto segments = splitPath(req.path);

    if (segments.size() < 2) {
        res.body = classListData();
        return res;
    }

    auto id = parseClassName(segments[1]);

    if (segments.size() == 2)
        return handleClassDetail(id.className);

    std::string subRoute = segments[2];
    return handleClassSubRoute(id.className, subRoute, segments);
}

// =========================================================================
// /classes/{class}/... — sub-route dispatch
// =========================================================================

HttpResponse WebsideServer::handleClassSubRoute(
    const std::string& className,
    const std::string& subRoute,
    const std::vector<std::string>& segments) const {

    HttpResponse res;

    if (subRoute == "subclasses")               res.body = subclassesData(className);
    else if (subRoute == "superclasses")         res.body = superclassesData(className);
    else if (subRoute == "variables")            res.body = variablesData(className);
    else if (subRoute == "instance-variables")   res.body = instanceVariablesData(className);
    else if (subRoute == "class-variables")      res.body = classVariablesData(className);
    else if (subRoute == "categories")           res.body = categoriesData(className);
    else if (subRoute == "used-categories")      res.body = usedCategoriesData(className);
    else if (subRoute == "selectors")            res.body = selectorsData(className);
    else if (subRoute == "methods") {
        if (segments.size() == 3) {
            res.body = methodsData(className);
        } else {
            std::string selector;
            for (size_t i = 3; i < segments.size(); i++) {
                if (i > 3) selector += "/";
                selector += segments[i];
            }
            res.body = methodDetailData(className, selector);
            if (res.body == "{}")
                res.statusCode = 404;
        }
    } else {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Unknown sub-route: " + subRoute).dump();
    }
    return res;
}

// =========================================================================
// Standard Webside API routes
// =========================================================================

void WebsideServer::setupBaseRoutes() {
    // ---- General ----

    sessionFreeRoute("GET", "/dialect", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::string(dialect()).dump();
        return res;
    });

    sessionFreeRoute("GET", "/version", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::string(version()).dump();
        return res;
    });

    setupStaticRoutes();
    setupLegacyFrameRoutes();
    setupRunControlRoutes();
}

// A client asks for these at startup. Their answers do not depend on the
// target, so they answer even while nothing is open.
void WebsideServer::setupStaticRoutes() {
    static const std::pair<const char*, const char*> fixedAnswers[] = {
        {"/logo", "\"\""},
        {"/themes", "[]"},
        // The documented shape is an object with the two dialect colors, and
        // the client reads both fields straight off it.
        {"/colors", "{\"primary\":\"#1976d2\",\"secondary\":\"#42a5f5\"}"},
        {"/extensions", "[]"},
        {"/icons", "[]"},
        {"/usual-categories", "[]"},
        {"/command-definitions", "[]"},
        {"/stats", "{}"},
        {"/objects", "[]"},
    };
    for (const auto& [path, body] : fixedAnswers) {
        sessionFreeRoute("GET", path, [body = body](const HttpRequest&) {
            HttpResponse res;
            res.body = body;
            return res;
        });
    }

    sessionFreeRoute("POST", "/autocompletions", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.routePrefix("GET", "/objects", [](const HttpRequest&) {
        HttpResponse res;
        res.statusCode = 404;
        res.body = Json::object().set("error", "Object not found").dump();
        return res;
    });
}

// The frame routes of the single-debugger API act on the primary thread.
void WebsideServer::setupLegacyFrameRoutes() {
    // ---- Frames ----

    server.route("GET", "/debuggers/1/frames", [this](const HttpRequest&) {
        HttpResponse res;
        if (isActive()) {
            res.body = listFrames();
            auto walked = session().vmThread();
            if (walked) warn(res, frameWarning(*walked));
        } else {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Debugger not found").dump();
        }
        return res;
    });

    server.routePrefix("GET", "/debuggers/1/frames", [this](const HttpRequest& req) {
        HttpResponse res;
        if (!isActive()) {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Debugger not found").dump();
            return res;
        }
        std::string tail = req.path.substr(std::string("/debuggers/1/frames/").size());
        std::string sub;
        auto slash = tail.find('/');
        if (slash != std::string::npos) {
            sub = tail.substr(slash + 1);
            tail = tail.substr(0, slash);
        }
        if (!isKnownFrameSubRoute(sub)) {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Unknown sub-route").dump();
            return res;
        }
        int index = 0;
        try { index = std::stoi(tail); } catch (...) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Invalid frame index").dump();
            return res;
        }
        if (sub == "bindings") {
            res.body = getFrameBindings(index);
        } else if (sub == "registers") {
            res.body = getFrameRegisters(index);
        } else {
            res.body = getFrameDetail(index);
            if (res.body == "{}") {
                res.statusCode = 404;
                res.body = Json::object().set("error", "Frame not found").dump();
            }
        }
        return res;
    });

}

// Resuming, suspending and reporting where the target stopped.
void WebsideServer::setupRunControlRoutes() {
    // ---- Debug control ----

    server.route("POST", "/debuggers/1/resume", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = runControlResult(resume());
        if (res.body.find("false") != std::string::npos)
            res.statusCode = 500;
        return res;
    });

    server.route("POST", "/debug/suspend", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = runControlResult(suspend());
        if (res.body.find("false") != std::string::npos)
            res.statusCode = 500;
        return res;
    });

    server.route("GET", "/debug/state", [this](const HttpRequest&) {
        HttpResponse res;
        auto p = pid();
        res.body = Json::object()
            .set("active", isActive())
            .set("pid", p ? *p : 0)
            .set("stopped", session().debugger().isStopped())
            .set("stopReason", stopReason())
            .dump();
        return res;
    });
}

// =========================================================================
// URL utilities
// =========================================================================

std::string WebsideServer::urlDecode(const std::string& encoded) {
    return HttpServer::urlDecode(encoded);
}

std::vector<std::string> WebsideServer::splitPath(const std::string& path) {
    std::vector<std::string> segments;
    std::istringstream stream(path);
    std::string segment;
    while (std::getline(stream, segment, '/')) {
        if (!segment.empty())
            segments.push_back(urlDecode(segment));
    }
    return segments;
}

} // namespace webside
