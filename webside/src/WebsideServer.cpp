#include "WebsideServer.h"
#include "Json.h"
#include <sstream>

namespace webside {

WebsideServer::WebsideServer(int port) : server(port) {}

void WebsideServer::run() {
    setupBaseRoutes();
    setupRoutes();
    server.run();
}

std::string WebsideServer::version() const { return "0.1.0"; }

std::string WebsideServer::getFrameDetail(int /*index*/) const { return "{}"; }
std::string WebsideServer::getFrameBindings(int /*index*/) const { return "[]"; }

std::string WebsideServer::nativeSymbolsData(const std::string& /*filter*/) const { return "[]"; }
std::string WebsideServer::nativeModulesData() const { return "[]"; }
std::string WebsideServer::nativeSymbolDetailData(const std::string& /*name*/) const { return "{}"; }
std::string WebsideServer::nativeInspectData(const std::string& /*expression*/) const { return "{}"; }

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

    server.route("GET", "/dialect", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::string(dialect()).dump();
        return res;
    });

    server.route("GET", "/version", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::string(version()).dump();
        return res;
    });

    server.route("GET", "/logo", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "\"\"";
        return res;
    });

    server.route("GET", "/themes", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/colors", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/extensions", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/icons", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/usual-categories", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/command-definitions", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.route("GET", "/stats", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "{}";
        return res;
    });

    server.route("GET", "/objects", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    server.routePrefix("GET", "/objects", [](const HttpRequest&) {
        HttpResponse res;
        res.statusCode = 404;
        res.body = "{\"error\":\"Object not found\"}";
        return res;
    });

    server.route("POST", "/autocompletions", [](const HttpRequest&) {
        HttpResponse res;
        res.body = "[]";
        return res;
    });

    // ---- Debugger listing ----

    server.route("GET", "/debuggers", [this](const HttpRequest&) {
        HttpResponse res;
        if (isActive()) {
            res.body = Json::array()
                .add(Json::object()
                    .set("id", 1)
                    .set("description", description())
                    .set("status", stopReason()))
                .dump();
        } else {
            res.body = "[]";
        }
        return res;
    });

    // ---- Frames ----

    server.route("GET", "/debuggers/1/frames", [this](const HttpRequest&) {
        HttpResponse res;
        if (isActive()) {
            res.body = listFrames();
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
        bool wantsBindings = false;
        auto bindingsPos = tail.find("/bindings");
        if (bindingsPos != std::string::npos) {
            wantsBindings = true;
            tail = tail.substr(0, bindingsPos);
        }
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
    });

    // ---- Debug control ----

    server.route("POST", "/debuggers/1/resume", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::object().set("success", resume()).dump();
        if (res.body.find("false") != std::string::npos)
            res.statusCode = 500;
        return res;
    });

    server.route("POST", "/debug/suspend", [this](const HttpRequest&) {
        HttpResponse res;
        res.body = Json::object().set("success", suspend()).dump();
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
