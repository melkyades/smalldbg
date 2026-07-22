#include "WebsideSession.h"
#include "Json.h"
#include "smalldbg/StackTrace.h"

namespace webside {

// =========================================================================
// Virtual frame-formatting hooks — generic native behavior. Dialect sessions
// override these to enrich frames with VM-specific information.
// =========================================================================

std::string WebsideSession::buildFrameLabel(const smalldbg::StackFrame& frame) const {
    if (!frame.moduleName.empty() && !frame.functionName.empty())
        return frame.moduleName + "!" + frame.functionName;
    if (!frame.functionName.empty())
        return frame.functionName;
    return "<unknown>";
}

std::string WebsideSession::buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                                 int index) const {
    auto j = Json::object()
        .set("index", index)
        .set("label", buildFrameLabel(frame));

    if (frame.metadata)
        addSmalltalkFrameDetail(j, frame);
    else
        addNativeFrameDetail(j, frame);

    j.set("interval", Json::object().set("start", 0).set("end", 0));
    return j.dump();
}

void WebsideSession::addSmalltalkFrameDetail(Json& j, const smalldbg::StackFrame& frame) const {
    j.set("class", Json::object()
        .set("name", frame.moduleName)
        .set("definition", "")
        .set("category", "vm"));
    j.set("method", Json::object()
        .set("selector", frame.functionName)
        .set("methodClass", frame.moduleName)
        .set("category", "vm")
        .set("source", frame.functionName));
}

void WebsideSession::addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const {
    std::string modName = frame.moduleName.empty() ? "<native>" : frame.moduleName;
    j.set("class", Json::object()
        .set("name", modName)
        .set("definition", "")
        .set("category", "native"));
    j.set("method", Json::object()
        .set("selector", frame.functionName)
        .set("methodClass", frame.moduleName)
        .set("category", "native")
        .set("source", frame.functionName.empty()
            ? std::string("<native code>")
            : frame.functionName + " (native code)"));
}

} // namespace webside
