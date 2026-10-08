#include "EggWebsideServer.h"
#include "EggInspectorJson.h"

namespace webside {

EggWebsideServer::EggWebsideServer(int port) : WebsideServer(port) {}

std::string EggWebsideServer::dialect() const     { return "Egg"; }
std::string EggWebsideServer::description() const { return "Egg Smalltalk"; }

std::unique_ptr<WebsideSession> EggWebsideServer::createSession() {
    return std::make_unique<EggDebugSession>();
}

// handleInspect only asks once the session has an inspector, which only an
// EggDebugSession has.
std::string EggWebsideServer::inspectJson(uint64_t oop, int maxSlots) const {
    auto& egg = static_cast<const EggDebugSession&>(*session);
    return inspectEggObject(egg.eggInspector(), oop, maxSlots);
}

} // namespace webside
