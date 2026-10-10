#pragma once

#include "HttpServer.h"
#include "WebsideSession.h"
#include "Workspace.h"
#include "smalldbg/Types.h"
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

    /** Resumes the target after the dialect's onPreResume hook. **/
    virtual bool resume();
    /** Suspends the target, then reads its classes and green threads again.
     **/
    virtual bool suspend();

    /** Sets up the routes and serves requests until the server stops. **/
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

    /** Returns the answer to a run-control request. An engine call refused
     *  while the target was moving is forgotten, since moving it was the
     *  point. **/
    std::string runControlResult(bool success) const;

    /** Returns why the frames of `thread` cannot be trusted, or an empty text
     *  when they can. The server sends it in a header, so that the frames
     *  keep their Webside shape. **/
    std::string frameWarning(smalldbg::Thread& thread) const;

    /** Returns the id of the OS thread the VM runs on, or 0 when it cannot be
     *  found. **/
    smalldbg::ThreadId vmThreadId() const;
    static void warn(HttpResponse& res, const std::string& warning);

    // ---- native symbol data ----
    std::string nativeSymbolsData(const std::string& filter) const;
    std::string nativeModulesData() const;
    std::string nativeSymbolDetailData(const std::string& name) const;
    std::string nativeInspectData(const std::string& expression) const;
    HttpResponse handleLoadModuleSymbols(const HttpRequest& req);
    HttpResponse handleSymbol(const HttpRequest& req) const;

    // ---- memory / disassembly routes ----
    HttpResponse handleMemory(const HttpRequest& req) const;
    HttpResponse handleMemoryTypesGet(const HttpRequest& req) const;
    HttpResponse handleMemoryTypesSet(const HttpRequest& req);
    HttpResponse handleMemoryTypesClear(const HttpRequest& req);
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
    HttpResponse handleDisassemble(const HttpRequest& req) const;

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

    // ---- VM inspector routes (delegate to the session inspector) ----
    /** Returns the VM's regions and the target's modules. A dialect may add
     *  what it knows about its own spaces. **/
    virtual HttpResponse handleRegions(const HttpRequest& req) const;
    HttpResponse handleClassify(const HttpRequest& req) const;
    Json regionJson(const vmdbg::Region& region) const;
    HttpResponse handleInspect(const HttpRequest& req) const;

    // ---- class / search route handlers ----
    HttpResponse handleClassList(const HttpRequest& req) const;
    HttpResponse handleClassDetail(const std::string& className) const;
    HttpResponse handleClassesPrefix(const HttpRequest& req) const;
    HttpResponse handleClassSubRoute(const std::string& className,
                                     const std::string& subRoute,
                                     const std::vector<std::string>& segments) const;

    // ---- hook for subclass-specific routes ----
    virtual void setupRoutes();

    /** Runs the debugger's thread to the address in the request body,
     *  forwards or backwards. **/
    HttpResponse handleRunTo(const HttpRequest& req, bool backwards);

    /** Performs the stepping action a /debuggers path names, on the thread
     *  its debugger id names. Returns false for an action it does not know.
     **/
    bool stepAction(const std::vector<std::string>& segments);

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

    /** Adds a route that answers even while no target is open. **/
    void sessionFreeRoute(const std::string& method, const std::string& path,
                          HttpHandler handler);

    /** Returns `address` in hex, at the target's width when one is open. **/
    Json workspaceAddress(uint64_t address) const;
    /** Returns the address a request body gives as a number or in hex, or 0
     *  when it gives none. **/
    static uint64_t addressIn(const Json& value);
    static HttpResponse badRequest(const std::string& error);

    // ---- URL utilities ----
    static std::string urlDecode(const std::string& encoded);
    static std::vector<std::string> splitPath(const std::string& path);
    static uint64_t parseHexParam(const std::string& s);
    /** Returns `position` the way the engine writes it, SEQ:STEP in hex. **/
    static std::string positionText(const smalldbg::TracePosition& position);
    /** Returns the request's number `key`, in decimal or in hex after "0x",
     *  or `dflt` when it is missing or not a number. **/
    static uint64_t param64(const HttpRequest& req, const char* key,
                            uint64_t dflt = 0);

private:
    void setupBaseRoutes();
    void setupStaticRoutes();
    void setupLegacyFrameRoutes();
    void setupRunControlRoutes();
    void setupWorkspaceRoutes();
    void setupMemoryTypeRoutes();
    HttpResponse handleLabelsGet(const HttpRequest& req) const;
    HttpResponse handleLabelsSet(const HttpRequest& req);
    Json memoryTypeJson(const vmdbg::MemTypeRange& range) const;
    uint64_t typeExtent(uint64_t start, vmdbg::MemType type, int structId) const;
    size_t readUpTo(uint64_t start, std::vector<uint8_t>& buffer) const;
    uint64_t stringExtent(uint64_t start, size_t unit) const;
    uint64_t codeExtent(uint64_t start) const;
    void setupSymbolRoutes();
    void setupInspectorRoutes();
    void setupDebuggerRoutes();
    void setupDebuggerActionRoutes();
    void setupTraceRoutes();
    Json tracePositionJson() const;
    bool seekTraceTo(std::string target);
    HttpResponse answerOrRefuse(const HttpRequest& request,
                                const HttpHandler& handler) const;

    std::set<std::string> sessionFree;
};

} // namespace webside
