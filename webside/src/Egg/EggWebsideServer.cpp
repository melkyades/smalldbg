#include "EggWebsideServer.h"
#include "../Json.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>
#include "smalldbg/Arm64Disasm.h"

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

    // POST actions for any debugger (resume, stepping, suspend, terminate)
    server.routePrefix("POST", "/debuggers", [this](const HttpRequest& req) {
        HttpResponse res;
        auto segments = splitPath(req.path);

        // POST /debuggers/<id>/resume
        if (segments.size() >= 3 && segments[2] == "resume") {
            res.body = Json::object().set("success", resume()).dump();
            return res;
        }

        // POST /debuggers/<id>/suspend
        if (segments.size() >= 3 && segments[2] == "suspend") {
            res.body = Json::object().set("success", suspend()).dump();
            return res;
        }

        // POST /debuggers/<id>/terminate
        if (segments.size() >= 3 && segments[2] == "terminate") {
            session->detach();
            res.body = Json::object().set("success", true).dump();
            return res;
        }

        // POST /debuggers/<id>/frames/<index>/<action>
        if (segments.size() >= 5 && segments[2] == "frames") {
            std::string action = segments[4];
            bool success = false;

            if (action == "stepinto")         success = session->step();
            else if (action == "stepover")    success = session->stepOver();
            else if (action == "stepout")     success = session->stepOut();
            else if (action == "reversestepinto")  success = session->stepBack();
            else if (action == "reversestepover")  success = session->reverseStepOver();
            else if (action == "reversestepout")   success = session->reverseStepOut();
            else {
                res.statusCode = 404;
                res.body = Json::object().set("error", "Unknown action: " + action).dump();
                return res;
            }

            res.body = Json::object().set("success", success).dump();
            return res;
        }

        res.statusCode = 404;
        res.body = Json::object().set("error", "Unknown action").dump();
        return res;
    });

    // ---- VM Inspector routes ----
    server.route("GET", "/regions", [this](const HttpRequest& req) {
        return handleRegions(req);
    });
    server.route("GET", "/classify", [this](const HttpRequest& req) {
        return handleClassify(req);
    });
    server.route("GET", "/inspect", [this](const HttpRequest& req) {
        return handleInspect(req);
    });
    server.route("GET", "/memory", [this](const HttpRequest& req) {
        return handleMemory(req);
    });
    server.route("GET", "/symbol", [this](const HttpRequest& req) {
        return handleSymbol(req);
    });
    server.route("GET", "/disassemble", [this](const HttpRequest& req) {
        return handleDisassemble(req);
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

// =========================================================================
// VM Inspector helpers
// =========================================================================

static uint64_t parseHexParam(const std::string& s) {
    if (s.empty()) return 0;
    try {
        return std::stoull(s, nullptr, 0);
    } catch (...) {
        return 0;
    }
}

static Json moduleToCodeZone(const smalldbg::ModuleInfo& mod) {
    return Json::object()
        .set("start", Json::hex(mod.loadAddress))
        .set("end", Json::hex(mod.endAddress))
        .set("size", static_cast<int64_t>(mod.endAddress - mod.loadAddress));
}

static Json slotToJson(int index, const egg::EggObject& slotObj) {
    auto slot = Json::object();
    slot.set("index", index);
    slot.set("raw", Json::hex(slotObj.oop()));

    if (slotObj.isSmallInteger()) {
        auto smi = slotObj.asSmallInteger();
        slot.set("type", "SmallInteger");
        slot.set("class", "SmallInteger");
        slot.set("value", smi.value());
    } else if (slotObj.isHeapObject()) {
        auto slotHeap = slotObj.asHeapObject();
        slot.set("type", "object");
        slot.set("class", slotHeap.className());
        slot.set("value", slotHeap.printString());
    } else {
        slot.set("type", "nil");
        slot.set("class", "UndefinedObject");
        slot.set("value", "nil");
    }
    return slot;
}

static size_t typeUnitSize(const std::string& type) {
    if (type == "uint16" || type == "int16") return 2;
    if (type == "uint32" || type == "int32") return 4;
    if (type == "uint64" || type == "int64") return 8;
    return 1;
}

static int64_t readTypedValue(const uint8_t* buf, size_t unitSize, bool isSigned) {
    uint64_t raw = 0;
    std::memcpy(&raw, buf, unitSize);
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

// =========================================================================
// VM Inspector handlers
// =========================================================================

HttpResponse EggWebsideServer::handleRegions(const HttpRequest&) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto* inspector = session->getInspector();
    auto* provider = session->getDebugger()->getSymbolProvider();
    auto result = Json::object();

    // Code zones from loaded modules
    auto codeZones = Json::object();
    auto modules = provider->getModules();
    for (auto& mod : modules)
        codeZones.set(mod.shortName, moduleToCodeZone(mod));
    result.set("codeZones", codeZones);

    // Evaluator stack
    auto evalState = inspector->readEvaluatorState();
    if (evalState.valid) {
        result.set("stack", Json::object()
            .set("base", Json::hex(evalState.stackBase))
            .set("sp", Json::hex(evalState.regSP))
            .set("bp", Json::hex(evalState.regBP)));
    } else {
        result.set("stack", Json::null());
    }

    // Modules list for additional context
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

HttpResponse EggWebsideServer::handleClassify(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto addrIt = req.params.find("address");
    if (addrIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(addrIt->second);
    auto* provider = session->getDebugger()->getSymbolProvider();
    auto* inspector = session->getInspector();

    auto result = Json::object();
    result.set("address", Json::hex(addr));

    // Check loaded modules
    std::string moduleName;
    auto modules = provider->getModules();
    for (auto& mod : modules) {
        if (addr >= mod.loadAddress && addr < mod.endAddress) {
            moduleName = mod.shortName;
            break;
        }
    }
    result.set("module", moduleName.empty() ? Json::null() : Json::string(moduleName));

    // Check evaluator stack
    auto evalState = inspector->readEvaluatorState();
    bool inStack = false;
    if (evalState.valid && evalState.stackBase != 0 && evalState.regSP > 0) {
        uint64_t stackStart = evalState.stackBase;
        uint64_t stackEnd = evalState.stackBase + evalState.regSP * 8;
        inStack = (addr >= stackStart && addr < stackEnd);
    }
    result.set("stack", inStack);

    // Symbol lookup
    auto sym = provider->getSymbolByAddress(addr);
    if (sym) {
        result.set("symbol", sym->name);
        result.set("offset", static_cast<int64_t>(addr - sym->address));
    } else {
        result.set("symbol", nullptr);
        result.set("offset", nullptr);
    }

    // Space classification — try to identify Egg heap objects
    result.set("space", nullptr);
    result.set("codeZone", moduleName.empty() ? Json::null() : Json::string(moduleName));

    res.body = result.dump();
    return res;
}

HttpResponse EggWebsideServer::handleInspect(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

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
    maxSlots = std::clamp(maxSlots, 0, 1024);

    auto* inspector = session->getInspector();
    auto obj = inspector->objectAt(addr);
    auto result = Json::object();
    result.set("oop", Json::hex(addr));

    if (obj.isSmallInteger()) {
        auto smi = obj.asSmallInteger();
        result.set("class", "SmallInteger");
        result.set("size", 0);
        result.set("hash", 0);
        result.set("flags", "0x00");
        result.set("isBits", false);
        result.set("isIndexed", false);
        result.set("isNamed", false);
        result.set("isExtended", false);
        result.set("value", smi.value());
        result.set("string", std::to_string(smi.value()));
        result.set("slots", Json::array());
        result.set("totalSlots", 0);
        result.set("truncated", false);
    } else if (obj.isHeapObject()) {
        auto heap = obj.asHeapObject();
        uint32_t totalSlots = heap.size();

        result.set("class", heap.className());
        result.set("size", static_cast<int64_t>(totalSlots));
        result.set("hash", static_cast<int64_t>(heap.hash()));
        result.set("flags", Json::hex(static_cast<uint32_t>(heap.flags())));
        result.set("isBits", heap.isBytes());
        result.set("isIndexed", heap.isArrayed());
        result.set("isNamed", heap.isNamed());
        result.set("isExtended", !heap.isSmallHeader());

        if (heap.isBytes()) {
            result.set("string", heap.bytesAsString());
            result.set("value", heap.printString());
        } else {
            result.set("string", nullptr);
            result.set("value", heap.printString());
        }

        int readCount = std::min(static_cast<int>(totalSlots), maxSlots);
        auto slotsArr = Json::array();
        for (int i = 0; i < readCount; i++)
            slotsArr.add(slotToJson(i, heap.objectSlotAt(i)));

        result.set("slots", slotsArr);
        result.set("totalSlots", static_cast<int64_t>(totalSlots));
        result.set("truncated", readCount < static_cast<int>(totalSlots));
    } else {
        result.set("class", "UndefinedObject");
        result.set("size", 0);
        result.set("hash", 0);
        result.set("flags", "0x00");
        result.set("isBits", false);
        result.set("isIndexed", false);
        result.set("isNamed", false);
        result.set("isExtended", false);
        result.set("value", nullptr);
        result.set("string", "nil");
        result.set("slots", Json::array());
        result.set("totalSlots", 0);
        result.set("truncated", false);
    }

    res.body = result.dump();
    return res;
}

HttpResponse EggWebsideServer::handleMemory(const HttpRequest& req) const {
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

    auto process = session->getDebugger()->getProcess();
    auto result = Json::object();
    result.set("address", Json::hex(addr));

    if (type == "bytes") {
        std::vector<uint8_t> buf(count);
        if (process->readMemory(addr, buf.data(), count) != smalldbg::Status::Ok) {
            res.statusCode = 400;
            res.body = Json::object().set("error", "Failed to read memory").dump();
            return res;
        }
        result.set("hex", formatHexDump(buf));
        result.set("ascii", formatAsciiDump(buf));
        result.set("size", count);
    } else if (type == "string") {
        std::vector<uint8_t> buf(count);
        process->readMemory(addr, buf.data(), count);
        std::string str;
        for (int i = 0; i < count && buf[i] != 0; i++)
            str += static_cast<char>(buf[i]);
        result.set("type", "string");
        result.set("value", str);
        result.set("size", static_cast<int64_t>(str.size()));
    } else {
        size_t unitSize = typeUnitSize(type);
        bool isSigned = !type.empty() && type[0] == 'i';
        size_t totalBytes = unitSize * count;
        totalBytes = std::min(totalBytes, static_cast<size_t>(32768));

        std::vector<uint8_t> buf(totalBytes, 0);
        process->readMemory(addr, buf.data(), totalBytes);

        auto values = Json::array();
        int actualCount = static_cast<int>(totalBytes / unitSize);
        for (int i = 0; i < actualCount; i++)
            values.add(readTypedValue(buf.data() + i * unitSize, unitSize, isSigned));

        result.set("type", type);
        result.set("values", values);
    }

    res.body = result.dump();
    return res;
}

HttpResponse EggWebsideServer::handleSymbol(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto nameIt = req.params.find("name");
    if (nameIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing name parameter").dump();
        return res;
    }

    auto* provider = session->getDebugger()->getSymbolProvider();
    auto sym = provider->getSymbolByName(nameIt->second);
    if (!sym) {
        res.statusCode = 404;
        res.body = Json::object().set("error", "Symbol not found").dump();
        return res;
    }

    auto result = symbolToJson(*sym);

    // Also read the value at the symbol address
    uint64_t value = 0;
    auto process = session->getDebugger()->getProcess();
    if (process->readMemory(sym->address, &value, 8) == smalldbg::Status::Ok)
        result.set("value", Json::hex(value));
    else
        result.set("value", nullptr);

    res.body = result.dump();
    return res;
}

HttpResponse EggWebsideServer::handleDisassemble(const HttpRequest& req) const {
    HttpResponse res;
    if (!isActive()) { res.body = "{}"; return res; }

    auto addrIt = req.params.find("address");
    if (addrIt == req.params.end()) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t addr = parseHexParam(addrIt->second);

    int count = 64;
    auto countIt = req.params.find("count");
    if (countIt != req.params.end()) {
        try { count = std::stoi(countIt->second); } catch (...) {}
    }
    count = std::clamp(count, 1, 4096);

    // Round count up to multiple of 4 (ARM64 instruction size)
    int byteCount = ((count + 3) / 4) * 4;
    byteCount = std::clamp(byteCount, 4, 4096);

    auto process = session->getDebugger()->getProcess();
    std::vector<uint8_t> buf(byteCount);
    if (process->readMemory(addr, buf.data(), byteCount) != smalldbg::Status::Ok) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Failed to read memory").dump();
        return res;
    }

    auto instructions = Json::array();
    for (int i = 0; i + 3 < byteCount; i += 4) {
        uint32_t insn = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24);
        char hexBytes[12];
        snprintf(hexBytes, sizeof(hexBytes), "%02X%02X%02X%02X",
                 buf[i], buf[i+1], buf[i+2], buf[i+3]);
        instructions.add(Json::object()
            .set("address", Json::hex(addr + i))
            .set("size", 4)
            .set("bytes", std::string(hexBytes))
            .set("text", smalldbg::disassembleOne(insn, addr + i)));
    }

    auto result = Json::object()
        .set("address", Json::hex(addr))
        .set("size", byteCount)
        .set("hex", formatHexDump(buf))
        .set("instructions", instructions);

    res.body = result.dump();
    return res;
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
