#pragma once

#include "VMInspector.h"
#include "WebsideSession.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"

#include <map>
#include <memory>
#include <optional>
#include <string>

namespace webside {

struct StubInspector : vmdbg::VMInspector {
    void add(vmdbg::Region region) { addRegion(std::move(region)); }
};

// Answers every query without a target behind it, so the parts of the session
// that do not read the debugger can be exercised on their own.
struct StubSession : WebsideSession {
    // Nothing is opened in an engine, so a target succeeds unless the test
    // named the one that must not.
    bool readsWithoutEngine(const vmdbg::TargetSpec&) const override {
        return true;
    }
    bool onTargetOpened(const vmdbg::TargetSpec& target) override {
        return target.path != "unopenable";
    }
    bool isActive() const override { return false; }
    std::optional<int> getPid() const override { return std::nullopt; }
    std::string getStopReason() const override { return ""; }
    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return ""; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override { return "{}"; }
    std::string getSmalltalkFrameBindings(int, int) const override { return "[]"; }
    std::string getSmalltalkStackContents(int, int frame) const override {
        lastSelectedFrame = frame;
        return "[]";
    }
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
    std::string search(const std::string&, bool, const std::string&,
                       const std::string&) const override { return "[]"; }
    // The shared implementation would go to a debugger; this records instead,
    // which is what lets a test see what the workspace re-applied.
    bool setBreakpoint(uint64_t address, const std::string& name = "") override {
        applied[address] = name;
        return true;
    }
    bool clearBreakpoint(uint64_t address) override {
        return applied.erase(address) != 0;
    }
    std::string listBreakpoints() const override { return "[]"; }
    std::string readMemory(uint64_t, size_t) const override { return "{}"; }
    std::string waitForEvent(int) override { return "{}"; }
    std::string describeObject(uint64_t, int, int) const override { return "{}"; }
    std::shared_ptr<smalldbg::Thread> vmThread() const override { return nullptr; }
    smalldbg::Debugger& debugger() const override { return *ownedDebugger; }
    vmdbg::VMInspector& inspector() const override { return *ownedInspector; }

    // Never attached and never asked to inspect, but always there, so the
    // session can hand out the references its interface promises.
    const std::unique_ptr<smalldbg::Debugger> ownedDebugger{
        std::make_unique<smalldbg::Debugger>(smalldbg::Mode::External,
                                             smalldbg::X64::instance())};
    const std::unique_ptr<StubInspector> ownedInspector{
        std::make_unique<StubInspector>()};

    std::map<uint64_t, std::string> applied;
    mutable int lastSelectedFrame{0};
};

// A session that opens its target in the debugger, for tests that launch the
// test target. It runs no VM, so the thread the target stopped on stands in
// for the VM's.
struct LiveSession : StubSession {
    bool readsWithoutEngine(const vmdbg::TargetSpec&) const override {
        return false;
    }
    bool onTargetOpened(const vmdbg::TargetSpec&) override { return true; }
    bool isActive() const override { return debugger().isAttached(); }
    std::shared_ptr<smalldbg::Thread> vmThread() const override {
        return debugger().getCurrentThread();
    }
};

} // namespace webside
