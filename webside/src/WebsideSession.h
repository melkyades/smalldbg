#pragma once

#include <string>
#include <vector>
#include <optional>

namespace smalldbg {
    class Debugger;
    struct StackFrame;
}

namespace webside {

class Json;  // forward declaration

/// Abstract interface for all Webside debug sessions.
///
/// Concrete sessions drive a real smalldbg::Debugger; DisconnectedSession
/// provides safe "disconnected" answers so callers never have to null-check
/// the session.
class WebsideSession {
public:
    virtual ~WebsideSession() = default;

    // ---- session lifecycle ----
    virtual bool launch(const std::string& target,
                        const std::vector<std::string>& args = {}) = 0;
    virtual bool attach(int pid) = 0;
    virtual void detach() = 0;
    virtual bool isActive() const = 0;
    virtual std::optional<int> getPid() const = 0;

    // ---- debug control ----
    virtual bool resume() = 0;
    virtual bool suspend() = 0;
    virtual bool step() = 0;
    virtual bool stepOver() = 0;
    virtual bool stepOver(int frameIndex) = 0;
    virtual bool stepOut() = 0;
    virtual bool stepBack() = 0;
    virtual bool reverseStepOver() = 0;
    virtual bool reverseStepOut() = 0;

    // ---- state queries ----
    virtual std::string getStopReason() const = 0;
    virtual std::string getRegisters() const = 0;

    // ---- underlying debugger ----
    virtual smalldbg::Debugger* getDebugger() const = 0;

protected:
    // ---- virtual hooks for frame formatting ----
    // Dialects override these; the base builds generic native JSON.

    /// Display label for a frame (used by listFrames).
    virtual std::string buildFrameLabel(const smalldbg::StackFrame& frame) const;

    /// JSON detail for one frame; dispatches to the smalltalk/native hook
    /// based on whether the frame carries processor metadata.
    virtual std::string buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                             int index) const;
    virtual void addSmalltalkFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;
    virtual void addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;
};

} // namespace webside
