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
