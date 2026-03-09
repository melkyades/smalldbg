#include "EggWebsideServer.h"
#include "../Json.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include <thread>
#include <chrono>

namespace webside {

EggWebsideServer::EggWebsideServer(int port) : WebsideServer(port) {}

bool EggWebsideServer::launch(const std::string& eggPath,
                               const std::vector<std::string>& args) {
    session = std::make_unique<EggDebugSession>();
    return session->launch(eggPath, args);
}

std::string EggWebsideServer::dialect() const     { return "Egg"; }
std::string EggWebsideServer::description() const { return "Egg Smalltalk"; }

bool        EggWebsideServer::isActive() const    { return session && session->isActive(); }
std::string EggWebsideServer::stopReason() const  { return session ? session->getStopReason() : ""; }

std::optional<int> EggWebsideServer::pid() const {
    return session ? session->getPid() : std::nullopt;
}

bool EggWebsideServer::resume()  { return session && session->resume(); }

bool EggWebsideServer::suspend() {
    if (!session || !session->suspend()) return false;
    session->discoverClasses();
    session->refreshGreenThreads();
    return true;
}

std::string EggWebsideServer::listFrames() const {
    return session ? session->listFrames(256) : "[]";
}

std::string EggWebsideServer::getFrameDetail(int index) const {
    return session ? session->getFrameDetail(index) : "{}";
}

std::string EggWebsideServer::getFrameBindings(int index) const {
    return session ? session->getFrameBindings(index) : "[]";
}

// ---- Routes ----

void EggWebsideServer::setupRoutes() {
    WebsideServer::setupRoutes();

    // ---- Multi-debugger routes ----
    // Override base class routes: debugger 1 = native, 2+ = Smalltalk green threads

    server.route("GET", "/debuggers", [this](const HttpRequest&) {
        HttpResponse res;
        if (!isActive()) {
            res.body = "[]";
            return res;
        }
        auto arr = Json::array();
        // Debugger 1: native C++ stack
        arr.add(Json::object()
            .set("id", 1)
            .set("description", "Native stack")
            .set("status", stopReason()));
        // Debuggers 2..n: Smalltalk green threads
        for (int i = 0; i < session->greenThreadCount(); i++) {
            arr.add(Json::object()
                .set("id", i + 2)
                .set("description", "Smalltalk: " +
                    session->getGreenThreadName(i))
                .set("status", stopReason()));
        }
        res.body = arr.dump();
        return res;
    });

    // Prefix handler for /debuggers/* (frames, resume, etc.)
    server.routePrefix("GET", "/debuggers", [this](const HttpRequest& req) {
        return handleDebuggerRoute(req);
    });

    // Resume for any debugger
    server.routePrefix("POST", "/debuggers", [this](const HttpRequest& req) {
        HttpResponse res;
        // POST /debuggers/<id>/resume
        auto segments = splitPath(req.path);
        if (segments.size() >= 3 && segments[2] == "resume") {
            res.body = Json::object().set("success", resume()).dump();
        } else {
            res.statusCode = 404;
            res.body = Json::object().set("error", "Unknown action").dump();
        }
        return res;
    });
}

// =========================================================================
// Data methods — delegate to session
// =========================================================================

std::string EggWebsideServer::classListData(const std::string& root,
                                             bool namesOnly) const {
    return session->listClasses(root, namesOnly);
}

std::string EggWebsideServer::classDetailData(const std::string& name) const {
    return session->getClass(name);
}

std::string EggWebsideServer::searchData(const std::string& text, bool ignoreCase,
                                          const std::string& condition,
                                          const std::string& type) const {
    return session->search(text, ignoreCase, condition, type);
}

std::string EggWebsideServer::subclassesData(const std::string& name) const {
    return session->getSubclasses(name);
}

std::string EggWebsideServer::superclassesData(const std::string& name) const {
    return session->getSuperclasses(name);
}

std::string EggWebsideServer::variablesData(const std::string& name) const {
    return session->getVariables(name);
}

std::string EggWebsideServer::instanceVariablesData(const std::string& name) const {
    return session->getInstanceVariables(name);
}

std::string EggWebsideServer::classVariablesData(const std::string& name) const {
    return session->getClassVariables(name);
}

std::string EggWebsideServer::categoriesData(const std::string& name) const {
    return session->getCategories(name);
}

std::string EggWebsideServer::usedCategoriesData(const std::string& name) const {
    return session->getUsedCategories(name);
}

std::string EggWebsideServer::selectorsData(const std::string& name) const {
    return session->getSelectors(name);
}

std::string EggWebsideServer::methodsData(const std::string& name) const {
    return session->getMethods(name);
}

std::string EggWebsideServer::methodDetailData(const std::string& className,
                                                const std::string& selector) const {
    return session->getMethod(className, selector);
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

std::string EggWebsideServer::nativeSymbolsData(const std::string& filter) const {
    auto* provider = session->getDebugger()->getSymbolProvider();
    auto symbols = provider->findSymbols(filter);
    auto arr = Json::array();
    for (auto& sym : symbols)
        arr.add(symbolToJson(sym));
    return arr.dump();
}

std::string EggWebsideServer::nativeModulesData() const {
    auto* provider = session->getDebugger()->getSymbolProvider();
    auto modules = provider->getModules();
    auto arr = Json::array();
    for (auto& mod : modules) {
        arr.add(Json::object()
            .set("path", mod.path)
            .set("name", mod.shortName)
            .set("loadAddress", Json::hex(mod.loadAddress))
            .set("endAddress", Json::hex(mod.endAddress))
            .set("symbolCount", static_cast<int64_t>(mod.symbolCount)));
    }
    return arr.dump();
}

std::string EggWebsideServer::nativeSymbolDetailData(const std::string& name) const {
    auto* provider = session->getDebugger()->getSymbolProvider();
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

        size_t start = pos;
        while (pos < expr.size() && expr[pos] != '.' &&
               !(expr[pos] == '-' && pos + 1 < expr.size() && expr[pos + 1] == '>'))
            pos++;

        step.fieldName = expr.substr(start, pos - start);
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

// Resolve a type through pointer/typedef/const/volatile wrappers
// to find the underlying struct/class type with fields.
static const smalldbg::NativeTypeInfo* resolveToStruct(
    const std::string& typeName, smalldbg::SymbolProvider* provider) {
    auto* info = provider->getTypeByName(typeName);
    if (!info) return nullptr;

    // Follow pointer/typedef/const/volatile chains
    int depth = 0;
    while (info && depth < 20) {
        if (info->kind == smalldbg::NativeTypeKind::Struct ||
            info->kind == smalldbg::NativeTypeKind::Class ||
            info->kind == smalldbg::NativeTypeKind::Union) {
            return info;
        }
        if (info->targetTypeName.empty()) return nullptr;
        info = provider->getTypeByName(info->targetTypeName);
        depth++;
    }
    return nullptr;
}

std::string EggWebsideServer::nativeInspectData(const std::string& expression) const {
    auto* provider = session->getDebugger()->getSymbolProvider();
    auto process = session->getDebugger()->getProcess();
    if (!provider || !process) return "{}";

    auto parsed = parseNativeExpression(expression);
    if (parsed.rootSymbol.empty()) return "{}";

    // Resolve the root symbol
    auto rootSym = provider->getSymbolByName(parsed.rootSymbol);
    if (!rootSym) return "{}";

    auto rootTypeName = provider->getVariableTypeName(parsed.rootSymbol);
    if (!rootTypeName) return "{}";

    uint64_t currentAddr = rootSym->address;
    std::string currentTypeName = *rootTypeName;

    // Walk the path steps
    for (auto& step : parsed.steps) {
        if (step.dereference) {
            // Read the pointer value at currentAddr
            uint64_t ptrVal = 0;
            if (process->readMemory(currentAddr, &ptrVal, 8) != smalldbg::Status::Ok)
                return "{}";
            currentAddr = ptrVal;
        }

        // Find the struct type that contains the field
        auto* structInfo = resolveToStruct(currentTypeName, provider);
        if (!structInfo) return "{}";

        // Find the field
        const smalldbg::NativeField* field = nullptr;
        for (auto& f : structInfo->fields) {
            if (f.name == step.fieldName) {
                field = &f;
                break;
            }
        }
        if (!field) return "{}";

        currentAddr += field->offset;
        currentTypeName = field->typeName;
    }

    // Read the value at the final address
    uint64_t rawValue = 0;
    auto* typeInfo = provider->getTypeByName(currentTypeName);
    size_t readSize = 8;
    if (typeInfo && typeInfo->size > 0 && typeInfo->size <= 8)
        readSize = static_cast<size_t>(typeInfo->size);
    process->readMemory(currentAddr, &rawValue, readSize);

    // Resolve fields to show (from the struct this points to, or from itself)
    std::vector<smalldbg::NativeField> visibleFields;
    auto* structInfo = resolveToStruct(currentTypeName, provider);
    if (structInfo)
        visibleFields = structInfo->fields;

    auto result = Json::object()
        .set("expression", expression)
        .set("address", Json::hex(currentAddr))
        .set("value", Json::hex(rawValue))
        .set("type", currentTypeName)
        .set("kind", typeKindString(typeInfo ? typeInfo->kind : smalldbg::NativeTypeKind::Unknown))
        .set("size", static_cast<int64_t>(typeInfo ? typeInfo->size : 0))
        .set("fields", fieldsToJson(visibleFields));

    return result.dump();
}

// ---- Multi-debugger route dispatcher ----

HttpResponse EggWebsideServer::handleDebuggerRoute(const HttpRequest& req) const {
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

    // Debugger 1: native C++ stack
    if (debuggerId == 1) {
        return handleNativeDebuggerRoute(segments);
    }

    // Debugger 2+: Smalltalk green threads (0-based index = debuggerId - 2)
    int threadIndex = debuggerId - 2;
    if (threadIndex < 0 || threadIndex >= session->greenThreadCount()) {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Debugger not found").dump();
        return res;
    }

    return handleSmalltalkDebuggerRoute(segments, threadIndex);
}

HttpResponse EggWebsideServer::handleNativeDebuggerRoute(
    const std::vector<std::string>& segments) const {
    HttpResponse res;

    // /debuggers/1
    if (segments.size() == 2) {
        res.body = Json::object()
            .set("id", 1)
            .set("description", "Native stack")
            .set("status", stopReason())
            .dump();
        return res;
    }

    // /debuggers/1/frames
    if (segments[2] == "frames") {
        if (segments.size() == 3) {
            res.body = listFrames();
            return res;
        }
        // /debuggers/1/frames/<idx>[/bindings]
        std::string tail = segments[3];
        bool wantsBindings = (segments.size() > 4 && segments[4] == "bindings");
        int index = 0;
        try { index = std::stoi(tail); } catch (...) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Invalid frame index").dump();
            return res;
        }
        if (wantsBindings) {
            res.body = getFrameBindings(index);
        } else {
            res.body = getFrameDetail(index);
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

HttpResponse EggWebsideServer::handleSmalltalkDebuggerRoute(
    const std::vector<std::string>& segments, int threadIndex) const {
    HttpResponse res;

    // /debuggers/<id>
    if (segments.size() == 2) {
        res.body = Json::object()
            .set("id", threadIndex + 2)
            .set("description", "Smalltalk: " +
                session->getGreenThreadName(threadIndex))
            .set("status", stopReason())
            .dump();
        return res;
    }

    // /debuggers/<id>/frames
    if (segments[2] == "frames") {
        if (segments.size() == 3) {
            res.body = session->listSmalltalkFrames(threadIndex);
            return res;
        }
        // /debuggers/<id>/frames/<idx>[/bindings]
        int index = 0;
        try { index = std::stoi(segments[3]); } catch (...) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Invalid frame index").dump();
            return res;
        }
        bool wantsBindings = (segments.size() > 4 && segments[4] == "bindings");
        if (wantsBindings) {
            res.body = session->getSmalltalkFrameBindings(threadIndex, index);
        } else {
            res.body = session->getSmalltalkFrameDetail(threadIndex, index);
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

} // namespace webside
