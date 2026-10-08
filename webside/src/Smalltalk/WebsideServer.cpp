#include "WebsideServer.h"
#include "Smalltalk/InspectorJson.h"
#include "Json.h"

#include <smalldbg/Debugger.h>
#include <smalldbg/symbols/SymbolProvider.h>

namespace smalltalk {

using webside::HttpRequest;
using webside::HttpResponse;
using webside::Json;

Inspector* WebsideServer::smalltalkInspector() const {
    return session().inspector().smalltalkView();
}

HttpResponse WebsideServer::handleRegions(const HttpRequest& req) const {
    Inspector* inspector = smalltalkInspector();
    if (!isActive() || !inspector)
        return webside::WebsideServer::handleRegions(req);

    // The spaces move when the VM collects garbage, so they are read again
    // on every request.
    inspector->refreshRegions();

    HttpResponse res;
    res.body = Json::object()
        .set("regions", Json::parse(webside::regionsJson(*inspector)))
        .dump();
    return res;
}

HttpResponse WebsideServer::handleClassify(const HttpRequest& req) const {
    Inspector* inspector = smalltalkInspector();
    if (!isActive() || !inspector)
        return webside::WebsideServer::handleClassify(req);

    auto address = req.params.find("address");
    if (address == req.params.end()) {
        HttpResponse res;
        res.statusCode = 400;
        res.body = Json::object()
            .set("error", "Missing address parameter").dump();
        return res;
    }

    uint64_t value = parseHexParam(address->second);
    auto result = Json::object()
        .set("address", Json::hex(value))
        .set("region", inspector->classifyAddress(value))
        .set("objectMemory", inspector->isInObjectMemory(value))
        .set("code", inspector->isCodeAddress(value));

    auto* provider = session().debugger().getSymbolProvider();
    if (auto symbol = provider->getSymbolByAddress(value)) {
        result.set("symbol", symbol->name);
        result.set("offset", static_cast<int64_t>(value - symbol->address));
    }

    HttpResponse res;
    res.body = result.dump();
    return res;
}

std::string WebsideServer::inspectJson(uint64_t oop, int maxSlots) const {
    Inspector* inspector = smalltalkInspector();
    if (!inspector) return "{}";
    return webside::inspectObjectJson(*inspector, oop, maxSlots);
}

HttpResponse WebsideServer::handleInspect(const HttpRequest& req) const {
    Inspector* inspector = smalltalkInspector();
    if (!isActive() || !inspector)
        return webside::WebsideServer::handleInspect(req);

    auto oop = req.params.find("oop");
    if (oop == req.params.end()) {
        HttpResponse res;
        res.statusCode = 400;
        res.body = Json::object().set("error", "Missing oop parameter").dump();
        return res;
    }

    int maxSlots = 64;
    auto slots = req.params.find("slots");
    if (slots != req.params.end()) {
        try { maxSlots = std::stoi(slots->second); } catch (...) {}
    }

    HttpResponse res;
    res.body = inspectJson(parseHexParam(oop->second), maxSlots);
    return res;
}

void WebsideServer::setupRoutes() {
    webside::WebsideServer::setupRoutes();

    // Why an object is still alive, the question behind every object that
    // should have been collected and was not.
    server.route("GET", "/retainers", [this](const HttpRequest& req) {
        HttpResponse res;
        Inspector* inspector = smalltalkInspector();
        auto oop = req.params.find("oop");
        res.body = isActive() && inspector && oop != req.params.end()
            ? webside::retainersJson(*inspector, parseHexParam(oop->second))
            : "[]";
        return res;
    });

    // The class of an object, without the object itself: a browser asks this
    // for every value it shows.
    server.route("GET", "/classoop", [this](const HttpRequest& req) {
        HttpResponse res;
        Inspector* inspector = smalltalkInspector();
        auto oop = req.params.find("oop");
        if (!inspector || oop == req.params.end()) {
            res.body = "{}";
            return res;
        }
        auto object = inspector->objectFor(parseHexParam(oop->second));
        if (!object || !object->isValid()) {
            res.body = "{}";
            return res;
        }
        res.body = Json::object()
            .set("oop", oop->second)
            .set("class", object->className())
            .set("printString", object->printString())
            .dump();
        return res;
    });
}

} // namespace smalltalk
