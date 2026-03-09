#pragma once

#include "HttpServer.h"
#include <string>
#include <vector>
#include <optional>

namespace webside {

/// Base class for Webside-compatible HTTP servers.
///
/// Sets up all standard Webside API routes (/dialect, /version, /debuggers,
/// /search, /classes, …) and delegates dialect-specific behavior to virtual
/// methods that subclasses override.
///
/// Subclasses provide data through the pure-virtual *Data() methods and may
/// add their own routes (e.g. /inspect, /debuggers) by overriding
/// setupRoutes() and calling the base implementation.
class WebsideServer {
public:
    explicit WebsideServer(int port);
    virtual ~WebsideServer() = default;

    /// Set up all routes and enter the accept loop (blocks).
    void run();

protected:
    HttpServer server;

    // ---- identity (subclass must implement) ----
    virtual std::string dialect() const = 0;
    virtual std::string version() const;
    virtual std::string description() const = 0;

    // ---- session state ----
    virtual bool isActive() const = 0;
    virtual std::string stopReason() const = 0;
    virtual std::optional<int> pid() const = 0;

    // ---- debug control ----
    virtual bool resume() = 0;
    virtual bool suspend() = 0;

    // ---- frame API ----
    virtual std::string listFrames() const = 0;
    virtual std::string getFrameDetail(int index) const;
    virtual std::string getFrameBindings(int index) const;

    // ---- class / search data (subclass must implement) ----
    virtual std::string classListData(const std::string& root = "",
                                      bool namesOnly = false) const = 0;
    virtual std::string classDetailData(const std::string& name) const = 0;
    virtual std::string searchData(const std::string& text, bool ignoreCase,
                                   const std::string& condition,
                                   const std::string& type) const = 0;
    virtual std::string subclassesData(const std::string& name) const = 0;
    virtual std::string superclassesData(const std::string& name) const = 0;
    virtual std::string variablesData(const std::string& name) const = 0;
    virtual std::string instanceVariablesData(const std::string& name) const = 0;
    virtual std::string classVariablesData(const std::string& name) const = 0;
    virtual std::string categoriesData(const std::string& name) const = 0;
    virtual std::string usedCategoriesData(const std::string& name) const = 0;
    virtual std::string selectorsData(const std::string& name) const = 0;
    virtual std::string methodsData(const std::string& name) const = 0;
    virtual std::string methodDetailData(const std::string& className,
                                         const std::string& selector) const = 0;

    // ---- native symbol data (optional — defaults return empty JSON) ----
    virtual std::string nativeSymbolsData(const std::string& filter) const;
    virtual std::string nativeModulesData() const;
    virtual std::string nativeSymbolDetailData(const std::string& name) const;
    virtual std::string nativeInspectData(const std::string& expression) const;

    // ---- class name parsing ----
    struct ClassIdent {
        std::string className;
        std::string baseName;
        bool isMetaclass;
    };
    static ClassIdent parseClassName(const std::string& name);

    // ---- class / search route handlers ----
    virtual HttpResponse handleClassList(const HttpRequest& req) const;
    HttpResponse handleClassDetail(const std::string& className) const;
    virtual HttpResponse handleClassesPrefix(const HttpRequest& req) const;
    HttpResponse handleClassSubRoute(const std::string& className,
                                     const std::string& subRoute,
                                     const std::vector<std::string>& segments) const;

    // ---- hook for subclass-specific routes ----
    virtual void setupRoutes();

    // ---- URL utilities ----
    static std::string urlDecode(const std::string& encoded);
    static std::vector<std::string> splitPath(const std::string& path);

private:
    void setupBaseRoutes();
};

} // namespace webside
