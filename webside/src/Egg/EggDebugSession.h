#pragma once

#include "../WebsideSession.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"
#include "EggInspector.h"
#include "../Json.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <cstdint>

namespace webside {

/// Manages a debug session for an Egg Smalltalk VM process.
///
/// Wraps `smalldbg::Debugger` in External mode to launch (or attach to)
/// an Egg executable, suspend/resume it, walk the native C++ stack, and
/// read Egg VM objects from the target process memory using readMemory().
///
/// VM introspection (object model, class discovery, evaluator stack
/// walking) is delegated to `egg::EggInspector`.
class EggDebugSession : public WebsideSession {
public:
    EggDebugSession();
    ~EggDebugSession() override;

    /// Launch the egg executable and attach the debugger.
    bool launch(const std::string& eggPath,
                const std::vector<std::string>& args = {}) override;

    /// Attach to an already-running egg process.
    bool attach(int pid) override;

    /// Detach from the target process.
    void detach() override;

    bool isActive() const override;
    std::optional<int> getPid() const override;

    // ---- Debug control ----
    bool resume() override;
    bool suspend() override;
    bool step() override;
    bool stepOver() override;
    bool stepOver(int frameIndex) override;
    bool stepOut() override;

    // ---- Reverse debug control (TTD) ----
    bool stepBack() override;
    bool reverseStepOver() override;
    bool reverseStepOut() override;

    // ---- State queries ----
    std::string getStopReason() const override;
    std::string getRegisters() const override;

    // ---- Breakpoints / memory / events / objects (interface stubs) ----
    bool setBreakpoint(uint64_t address, const std::string& name = "") override;
    bool clearBreakpoint(uint64_t address) override;
    std::string listBreakpoints() const override;
    std::string readMemory(uint64_t address, size_t size) const override;
    std::string waitForEvent(int timeoutMs = 5000) override;
    std::string describeObject(uint64_t handle, size_t maxDepth = 1) const override;

    // ---- Smalltalk-level debugging (green threads) ----

    // Type aliases — types live in EggInspector, re-exported here for
    // convenience so callers don't need to qualify them.
    using EvaluatorState = egg::EggInspector::EvaluatorState;
    using SmalltalkFrame = egg::EggInspector::SmalltalkFrame;

    /// A green thread represents one Smalltalk Process / evaluator context.
    struct GreenThread {
        int id{0};                 // starts at 1
        std::string name;          // descriptive label
        EvaluatorState state;
        std::vector<SmalltalkFrame> frames;
    };

    /// Refresh the list of green threads by reading the evaluator state.
    void refreshGreenThreads() override;

    /// Number of available green threads.
    int greenThreadCount() const override;

    /// Get the name of a green thread by index (0-based).
    std::string getGreenThreadName(int threadIndex) const override;

    /// Smalltalk-level frame listing for a green thread (JSON array).
    std::string listSmalltalkFrames(int threadIndex) const override;

    /// Smalltalk-level frame detail for a green thread (JSON object).
    std::string getSmalltalkFrameDetail(int threadIndex, int frameIndex) const override;

    /// Smalltalk-level frame bindings for a green thread (JSON array).
    std::string getSmalltalkFrameBindings(int threadIndex, int frameIndex) const override;

    // ---- Class browsing (delegates to inspector + JSON formatting) ----
    bool discoverClasses() override { return inspector->discoverClasses(); }
    std::string listClasses(const std::string& root = "",
                            bool namesOnly = false,
                            bool tree = false,
                            int depth = -1) const override;
    std::string getClass(const std::string& name) const override;
    std::string getSubclasses(const std::string& name) const override;
    std::string getSuperclasses(const std::string& name) const override;
    std::string getVariables(const std::string& name) const override;
    std::string getInstanceVariables(const std::string& name) const override;
    std::string getClassVariables(const std::string& name) const override;
    std::string getCategories(const std::string& name) const override;
    std::string getUsedCategories(const std::string& name) const override;
    std::string getSelectors(const std::string& name) const override;
    std::string getMethods(const std::string& name) const override;
    std::string getMethod(const std::string& className,
                          const std::string& selector) const override;
    std::string search(const std::string& text, bool ignoreCase,
                       const std::string& condition,
                       const std::string& type) const override;

    /// Underlying debugger (for low-level access).
    smalldbg::Debugger* getDebugger() const override { return debugger.get(); }

    /// Access the Egg VM inspector (covariant override of WebsideSession).
    egg::EggInspector* getInspector() const override { return inspector.get(); }

protected:
    /// Native frame detail enriched with source text and the IP interval.
    std::string buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                     int index) const override;

private:
    std::unique_ptr<smalldbg::Debugger> debugger;
    std::unique_ptr<egg::EggInspector> inspector;

    // ---- Green thread list ----
    std::vector<GreenThread> greenThreads;

    // ---- JSON helpers ----
    using ClassEntry = egg::EggInspector::ClassEntry;
    Json classInfoToJson(const ClassEntry& entry) const;
    std::string determinePackage(const ClassEntry& entry) const;

    // ---- Helpers ----
    std::string stopReasonStr(smalldbg::StopReason r) const;
};

} // namespace webside
