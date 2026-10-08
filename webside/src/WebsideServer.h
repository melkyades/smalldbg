#pragma once

#include "HttpServer.h"
#include "WebsideSession.h"
#include "Workspace.h"
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <set>

namespace webside {

/** A WebsideServer serves the Webside API from the session its workspace
 *  has open. While none is open, it refuses every request but those that do
 *  not need a target. Each dialect has a subclass, which overrides only what
 *  is particular to the dialect, such as how its objects are inspected. **/
class WebsideServer {
public:
    WebsideServer(Workspace& workspace, int port);
    virtual ~WebsideServer() = default;

    /// Resume / suspend the target (also drive startup from main()).
    virtual bool resume();
    virtual bool suspend();

    /// Set up all routes and enter the accept loop (blocks).
    void run();

protected:
    HttpServer server;
    Workspace& workspace;

    /** Returns the open session. Only a route that needs no target runs
     *  while none is open, and it does not call this. **/
    WebsideSession& session() const { return *workspace.session(); }

    // ---- identity (subclass must implement) ----
    virtual std::string dialect() const = 0;
    virtual std::string version() const;
    virtual std::string description() const = 0;

    // ---- session state (delegate to the session) ----
    virtual bool isActive() const;
    virtual std::string stopReason() const;
    virtual std::optional<int> pid() const;

    // ---- frame API (resolve the thread/frame, then delegate to the session) ----
    virtual std::string listFrames() const;
    virtual std::string getFrameDetail(int index) const;
    virtual std::string getFrameBindings(int index) const;
    virtual std::string getFrameRegisters(int index) const;
    /** Returns what `slots` stack slots from `from` are on the stack of
     *  `thread`: the frame that owns each and the role it has there. The
     *  slots' contents come from /memory. **/
    virtual std::string stackDescriptors(smalldbg::Thread& thread,
                                         int selectedIndex, uint64_t from,
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
    HttpResponse handleLoadModuleSymbols(const HttpRequest& req);
    HttpResponse handleSymbol(const HttpRequest& req) const;

    // ---- memory / disassembly routes ----
    HttpResponse handleMemory(const HttpRequest& req) const;
    /** Sets the hex dump of `count` bytes at `address`, and their ASCII
     *  rendering, in `result`. Returns false when they cannot be read. **/
    bool readByteDump(uint64_t address, int count, Json& result) const;
    /** Sets the C string at `address` in `result`, up to its terminator or
     *  `count` bytes. Returns false when the bytes cannot be read. **/
    bool readStringAt(uint64_t address, int count, Json& result) const;
    /** Sets `count` values of `type`, such as "int32", read from `address`, in
     *  `result`. With `asHex` the values are hex strings, which keeps 64-bit
     *  values exact. Returns false when the values cannot be read. **/
    bool readTypedUnits(uint64_t address, int count, const std::string& type,
                        bool asHex, Json& result) const;
    static Json unitJson(const uint8_t* unit, size_t unitSize, bool isSigned,
                         bool asHex);
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
        const std::vector<std::string>& segments, const HttpRequest& req,
        int threadIndex, int debuggerId) const;

    // Native OS threads ordered with the primary thread first (id = index+1).
    std::vector<std::shared_ptr<smalldbg::Thread>> nativeThreads() const;
    /** Returns why the frames of `thread` cannot be trusted, or an empty text
     *  when they can. The server sends it in a header, so that the frames
     *  keep their Webside shape. **/
    std::string frameWarning(smalldbg::Thread& thread) const;
    static void warn(HttpResponse& res, const std::string& warning);
    /** Returns the answer to a run-control request. An engine call refused
     *  while the target was moving is forgotten, since moving it was the
     *  point. **/
    std::string runControlResult(bool success) const;
    /** Returns the id of the OS thread the VM runs on, or 0 when it cannot be
     *  found. **/
    smalldbg::ThreadId vmThreadId() const;
    /** Returns the /debuggers listing: one debugger per thread. **/
    std::string debuggerListJson() const;
    /** Returns the /threads listing, each thread named by what it was started
     *  to do. A thread with no registers or stack is left out. **/
    std::string threadListJson() const;
    /** Returns one native thread's /threads entry, or null when the thread
     *  has no registers or stack. `main` is the id of the VM's thread. **/
    Json nativeThreadJson(smalldbg::Thread& thread, int id,
                          smalldbg::ThreadId main) const;
    void addGreenThreadDebuggers(Json& array, int id) const;
    void addGreenThreads(Json& array, int id) const;

    // ---- VM inspector routes (delegate to session->inspector()) ----
    virtual HttpResponse handleRegions(const HttpRequest& req) const;
    virtual HttpResponse handleClassify(const HttpRequest& req) const;
    virtual HttpResponse handleInspect(const HttpRequest& req) const;

    /// One object as a document. Only a dialect knows how its objects look,
    /// so the base has nothing to say.
    virtual std::string inspectJson(uint64_t oop, int maxSlots) const;

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

    /** Runs the debugger's thread to the address in the request body,
     *  forwards or backwards. **/
    HttpResponse handleRunTo(const HttpRequest& req, bool backwards);

    // ---- hook for subclass-specific routes ----
    virtual void setupRoutes();

    /** Adds a route that answers even while no target is open. **/
    void sessionFreeRoute(const std::string& method, const std::string& path,
                          HttpHandler handler);

    // ---- URL utilities ----
    static std::string urlDecode(const std::string& encoded);
    static std::vector<std::string> splitPath(const std::string& path);
    static uint64_t parseHexParam(const std::string& s);

private:
    void setupBaseRoutes();
    HttpResponse answerOrRefuse(const HttpRequest& request,
                                const HttpHandler& handler) const;

    std::set<std::string> sessionFree;
};

} // namespace webside
