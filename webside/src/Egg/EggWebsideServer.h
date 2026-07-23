#pragma once

#include "../WebsideServer.h"
#include "../Json.h"
#include "EggDebugSession.h"
#include <memory>
#include <cstdint>

namespace webside {

/// Webside server for the Egg C++ VM — uses the smalldbg API to
/// launch/attach to an egg process, suspend/resume it, walk its native
/// stack, read objects via readMemory, and expose class browsing, frame
/// detail, and search through the standard Webside HTTP routes.
class EggWebsideServer : public WebsideServer {
public:
    explicit EggWebsideServer(int port);

protected:
    // ---- WebsideServer overrides ----
    std::string dialect() const override;
    std::string description() const override;
    std::unique_ptr<WebsideSession> createSession() override;

    std::string listFrames() const override;
    std::string getFrameDetail(int index) const override;
    std::string getFrameBindings(int index) const override;

    void setupRoutes() override;

private:
    EggDebugSession* eggSession() const { return static_cast<EggDebugSession*>(session.get()); }

    // ---- Multi-debugger helpers ----
    HttpResponse handleDebuggerRoute(const HttpRequest& req) const;
    HttpResponse handleNativeDebuggerRoute(
        const std::vector<std::string>& segments) const;
    HttpResponse handleSmalltalkDebuggerRoute(
        const std::vector<std::string>& segments, int threadIndex) const;

    // ---- VM Inspector handlers ----
    HttpResponse handleRegions(const HttpRequest& req) const;
    HttpResponse handleClassify(const HttpRequest& req) const;
    HttpResponse handleInspect(const HttpRequest& req) const;
    HttpResponse handleMemory(const HttpRequest& req) const;
    HttpResponse handleDisassemble(const HttpRequest& req);
};

} // namespace webside
