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

    bool resume() override { return false; }
    bool suspend() override { return false; }
    bool step() override { return false; }
    bool stepOver() override { return false; }
    bool stepOver(int) override { return false; }
    bool stepOut() override { return false; }
    bool stepBack() override { return false; }
    bool reverseStepOver() override { return false; }
    bool reverseStepOut() override { return false; }

    std::string getStopReason() const override { return ""; }
    std::string getRegisters() const override { return "{}"; }

    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return ""; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override { return "{}"; }
    std::string getSmalltalkFrameBindings(int, int) const override { return "[]"; }

    smalldbg::Debugger* getDebugger() const override { return nullptr; }
};

} // namespace webside
