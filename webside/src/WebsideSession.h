#pragma once

#include <string>
#include <vector>
#include <optional>

namespace smalldbg {
    class Debugger;
}

namespace webside {

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

    // ---- underlying debugger ----
    virtual smalldbg::Debugger* getDebugger() const = 0;
};

} // namespace webside
