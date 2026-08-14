#pragma once

#include "HttpServer.h"
#include "WebsideSession.h"
#include "DisconnectedSession.h"
#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace webside {

/// Base class for Webside-compatible HTTP servers.
///
/// Owns a WebsideSession (a DisconnectedSession null-object until a target is
/// attached) and delegates the Webside API to it. Subclasses supply the session
/// type via createSession() and override only dialect-specific behavior (VM
/// inspector routes, native symbols, …).
class WebsideServer {
public:
    explicit WebsideServer(int port);
    virtual ~WebsideServer() = default;

    /// Create the session, launch the target, then serve.
    virtual bool launch(const std::string& target,
                        const std::vector<std::string>& args = {});

    /// Resume / suspend the target (also drive startup from main()).
    virtual bool resume();
    virtual bool suspend();

    /// Open a replayable trace (e.g. a TTD .run) instead of launching.
    /// Base default: unsupported. Dialects that support time-travel override it.
    virtual bool openTrace(const std::string& tracePath,
                           const std::string& sourcePath = {});

    /// Open a crash/WER dump (.dmp) as a frozen snapshot instead of launching.
    /// Base default: unsupported. Dialects that support dumps override it.
    virtual bool openDump(const std::string& dumpPath);

    /// Set up all routes and enter the accept loop (blocks).
    void run();

protected:
    HttpServer server;
    std::unique_ptr<WebsideSession> session{std::make_unique<DisconnectedSession>()};

    // ---- identity (subclass must implement) ----
    virtual std::string dialect() const = 0;
    virtual std::string version() const;
    virtual std::string description() const = 0;

    /// Factory — subclass returns the session type for its dialect.
    virtual std::unique_ptr<WebsideSession> createSession() = 0;

    // ---- session state (delegate to the session) ----
    virtual bool isActive() const;
    virtual std::string stopReason() const;
    virtual std::optional<int> pid() const;

    // ---- frame API (resolve the thread/frame, then delegate to the session) ----
    virtual std::string listFrames() const;
    virtual std::string getFrameDetail(int index) const;
    virtual std::string getFrameBindings(int index) const;
    virtual std::string getFrameRegisters(int index) const;
    /// What the addresses in [from, to) mean on the current stack. Contents
    /// come from /memory; this says which frame owns a slot and what it holds.
    virtual std::string stackDescriptors(int selectedIndex, uint64_t from,
                                         int slots) const;

    // ---- class / search data (delegate to the session) ----
    virtual std::string classListData(const std::string& root = "",
                                      bool namesOnly = false) const;
    virtual std::string classDetailData(const std::string& name) const;
    virtual std::string searchData(const std::string& text, bool ignoreCase,
                                   const std::string& condition,
                                   const std::string& type) const;
    virtual std::string subclassesData(const std::string& name) const;
    virtual std::string superclassesData(const std::string& name) const;
    virtual std::string variablesData(const std::string& name) const;
    virtual std::string instanceVariablesData(const std::string& name) const;
    virtual std::string classVariablesData(const std::string& name) const;
    virtual std::string categoriesData(const std::string& name) const;
    virtual std::string usedCategoriesData(const std::string& name) const;
    virtual std::string selectorsData(const std::string& name) const;
    virtual std::string methodsData(const std::string& name) const;
    virtual std::string methodDetailData(const std::string& className,
                                         const std::string& selector) const;

    // ---- native symbol data ----
    virtual std::string nativeSymbolsData(const std::string& filter) const;
    virtual std::string nativeModulesData() const;
    virtual std::string nativeSymbolDetailData(const std::string& name) const;
    virtual std::string nativeInspectData(const std::string& expression) const;
    HttpResponse handleSymbol(const HttpRequest& req) const;

    // ---- memory / disassembly routes ----
    HttpResponse handleMemory(const HttpRequest& req) const;
    virtual HttpResponse handleDisassemble(const HttpRequest& req);

    // ---- suspend/resume hooks (dialects may set up / tear down VM state) ----
    virtual void onPostSuspend() {}
    virtual void onPreResume() {}

    // ---- /debuggers routes ----
    // Debugger ids: native OS threads are 1..N (primary first), then any
    // green (Smalltalk) threads are N+1..N+M. Frame walking and stepping act
    // on the thread the id resolves to.
    HttpResponse handleDebuggerRoute(const HttpRequest& req) const;
    HttpResponse handleNativeDebuggerRoute(
        const std::vector<std::string>& segments, const HttpRequest& req,
        smalldbg::Thread& thread, int debuggerId) const;
    HttpResponse handleSmalltalkDebuggerRoute(
        const std::vector<std::string>& segments, int threadIndex,
        int debuggerId) const;

    // Native OS threads ordered with the primary thread first (id = index+1).
    std::vector<std::shared_ptr<smalldbg::Thread>> nativeThreads() const;

    // ---- VM inspector routes (delegate to session->getInspector()) ----
    virtual HttpResponse handleRegions(const HttpRequest& req) const;
    virtual HttpResponse handleClassify(const HttpRequest& req) const;
    virtual HttpResponse handleInspect(const HttpRequest& req) const;

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
    static uint64_t parseHexParam(const std::string& s);

private:
    void setupBaseRoutes();
};

} // namespace webside
