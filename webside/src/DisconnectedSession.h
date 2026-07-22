#pragma once

#include "WebsideSession.h"

namespace webside {

/// Null-object session used when no target process is attached.
///
/// Answers every query with a safe "disconnected" value (false, no pid, no
/// debugger), so callers never need to null-check the session pointer.
class DisconnectedSession : public WebsideSession {
public:
    bool launch(const std::string&, const std::vector<std::string>& = {}) override { return false; }
    bool attach(int) override { return false; }
    void detach() override {}
    bool isActive() const override { return false; }
    std::optional<int> getPid() const override { return std::nullopt; }
    smalldbg::Debugger* getDebugger() const override { return nullptr; }
};

} // namespace webside
