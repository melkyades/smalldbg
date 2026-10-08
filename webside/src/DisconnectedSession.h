#pragma once

#include "WebsideSession.h"

#include <smalldbg/Debugger.h>

#include <memory>

namespace webside {

/** A DisconnectedSession stands in for a session while no target is open. It
 *  never opens one: every query gets an empty answer, and run control fails.
 **/
class DisconnectedSession : public WebsideSession {
public:
    bool isActive() const override { return false; }
    std::optional<int> getPid() const override { return std::nullopt; }

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

    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, size_t) const override { return "{}"; }

    smalldbg::Debugger& debugger() const override { return *ownedDebugger; }
    vmdbg::VMInspector& inspector() const override { return *ownedInspector; }
    std::shared_ptr<smalldbg::Thread> vmThread() const override { return nullptr; }

protected:
    // Nothing is opened in the debugger, and no target is accepted.
    bool readsWithoutEngine(const vmdbg::TargetSpec&) const override { return true; }
    bool onTargetOpened(const vmdbg::TargetSpec&) override { return false; }

private:
    struct NoInspector : vmdbg::VMInspector {
        StackRegion evaluatorStack() const override { return {}; }
    };

    std::unique_ptr<smalldbg::Debugger> ownedDebugger{
        std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External)};
    std::unique_ptr<vmdbg::VMInspector> ownedInspector{std::make_unique<NoInspector>()};
};

} // namespace webside
