#include "EggWebsideServer.h"

namespace webside {

EggWebsideServer::EggWebsideServer(int port) : WebsideServer(port) {}

std::string EggWebsideServer::dialect() const     { return "Egg"; }
std::string EggWebsideServer::description() const { return "Egg Smalltalk"; }

std::unique_ptr<WebsideSession> EggWebsideServer::createSession() {
    return std::make_unique<EggDebugSession>();
}

} // namespace webside
