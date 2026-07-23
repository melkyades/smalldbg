#include "EggWebsideServer.h"
#include "../Json.h"
#include "smalldbg/SymbolProvider.h"
#include "smalldbg/Process.h"
#include "smalldbg/Debugger.h"
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>

#include "smalldbg/Disassembler.h"

namespace webside {

EggWebsideServer::EggWebsideServer(int port) : WebsideServer(port) {}

std::string EggWebsideServer::dialect() const     { return "Egg"; }
std::string EggWebsideServer::description() const { return "Egg Smalltalk"; }

std::unique_ptr<WebsideSession> EggWebsideServer::createSession() {
    return std::make_unique<EggDebugSession>();
}

std::string EggWebsideServer::listFrames() const {
    return isActive() ? eggSession()->listFrames(256) : "[]";
}

std::string EggWebsideServer::getFrameDetail(int index) const {
    return isActive() ? eggSession()->getFrameDetail(index) : "{}";
}

std::string EggWebsideServer::getFrameBindings(int index) const {
    return isActive() ? eggSession()->getFrameBindings(index) : "[]";
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
    server.route("GET", "/disassemble", [this](const HttpRequest& req) {
        return handleDisassemble(req);
    });
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

    auto* inspector = eggSession()->getInspector();
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
    auto* inspector = eggSession()->getInspector();

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

    auto* inspector = eggSession()->getInspector();
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


HttpResponse EggWebsideServer::handleDisassemble(const HttpRequest& req) {
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

    auto process = session->getDebugger()->getProcess();
    std::vector<uint8_t> buf(byteCount);
    if (process->readMemory(addr, buf.data(), byteCount) != smalldbg::Status::Ok) {
        res.statusCode = 400;
        res.body = Json::object().set("error", "Failed to read memory").dump();
        return res;
    }

        smalldbg::Disassembler *dis = session->getDebugger()->getDisassembler();
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
