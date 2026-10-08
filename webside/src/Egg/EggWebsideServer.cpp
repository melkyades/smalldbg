#include "EggWebsideServer.h"
#include "EggInspectorJson.h"

namespace webside {

std::string EggWebsideServer::dialect() const     { return "Egg"; }
std::string EggWebsideServer::description() const { return "Egg Smalltalk"; }

// The workspace only ever opens an EggDebugSession here.
std::string EggWebsideServer::inspectJson(uint64_t oop, int maxSlots) const {
    auto& egg = static_cast<const EggDebugSession&>(session());
    return inspectEggObject(egg.eggInspector(), oop, maxSlots);
}

} // namespace webside
