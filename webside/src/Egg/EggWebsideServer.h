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


    void setupRoutes() override;

private:
    EggDebugSession* eggSession() const { return static_cast<EggDebugSession*>(session.get()); }

    // ---- Multi-debugger helpers ----

    // ---- VM Inspector handlers ----
    HttpResponse handleRegions(const HttpRequest& req) const;
    HttpResponse handleClassify(const HttpRequest& req) const;
    HttpResponse handleInspect(const HttpRequest& req) const;
};

} // namespace webside
