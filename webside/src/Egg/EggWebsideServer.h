#pragma once

#include "../WebsideServer.h"
#include "EggDebugSession.h"
#include <memory>

namespace webside {

/// Webside server for the Egg Smalltalk VM.
///
/// A thin dialect front end: it only names the dialect and builds an
/// EggDebugSession. All Webside HTTP behavior lives in WebsideServer, which
/// delegates to the session (a WebsideSession) and its VMInspector.
class EggWebsideServer : public WebsideServer {
public:
    explicit EggWebsideServer(int port);

protected:
    std::string dialect() const override;
    std::string description() const override;
    std::unique_ptr<WebsideSession> createSession() override;
    std::string inspectJson(uint64_t oop, int maxSlots) const override;
};

} // namespace webside
