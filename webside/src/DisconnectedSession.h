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
    std::string getSmalltalkStackContents(int) const override { return "[]"; }

    bool discoverClasses() override { return false; }
    std::string listClasses(const std::string&, bool, bool, int) const override { return "[]"; }
    std::string getClass(const std::string&) const override { return "{}"; }
    std::string getSubclasses(const std::string&) const override { return "[]"; }
    std::string getSuperclasses(const std::string&) const override { return "[]"; }
    std::string getVariables(const std::string&) const override { return "[]"; }
    std::string getInstanceVariables(const std::string&) const override { return "[]"; }
    std::string getClassVariables(const std::string&) const override { return "[]"; }
    std::string getCategories(const std::string&) const override { return "[]"; }
    std::string getUsedCategories(const std::string&) const override { return "[]"; }
    std::string getSelectors(const std::string&) const override { return "[]"; }
    std::string getMethods(const std::string&) const override { return "[]"; }
    std::string getMethod(const std::string&, const std::string&) const override { return "{}"; }
    std::string search(const std::string&, bool, const std::string&, const std::string&) const override { return "[]"; }

    bool setBreakpoint(uint64_t, const std::string&) override { return false; }
    bool clearBreakpoint(uint64_t) override { return false; }
    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, size_t) const override { return "{}"; }

    smalldbg::Debugger* getDebugger() const override { return nullptr; }
    WebsideInspector* getInspector() const override { return nullptr; }
};

} // namespace webside
