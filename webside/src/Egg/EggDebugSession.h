#pragma once

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
class EggDebugSession {
public:
    EggDebugSession();
    ~EggDebugSession();

    /// Launch the egg executable and attach the debugger.
    bool launch(const std::string& eggPath,
                const std::vector<std::string>& args = {});

    /// Attach to an already-running egg process.
    bool attach(int pid);

    /// Detach from the target process.
    void detach();

    bool isActive() const;
    std::optional<int> getPid() const;

    // ---- Debug control ----
    bool resume();
    bool suspend();
    bool step();

    // ---- State queries ----
    std::string getStopReason() const;
    std::string listFrames(size_t maxFrames = 256) const;
    std::string getFrameDetail(int index) const;
    std::string getFrameBindings(int index) const;

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
    void refreshGreenThreads();

    /// Number of available green threads.
    int greenThreadCount() const;

    /// Get the name of a green thread by index (0-based).
    std::string getGreenThreadName(int threadIndex) const;

    /// Smalltalk-level frame listing for a green thread (JSON array).
    std::string listSmalltalkFrames(int threadIndex) const;

    /// Smalltalk-level frame detail for a green thread (JSON object).
    std::string getSmalltalkFrameDetail(int threadIndex, int frameIndex) const;

    /// Smalltalk-level frame bindings for a green thread (JSON array).
    std::string getSmalltalkFrameBindings(int threadIndex, int frameIndex) const;

    // ---- Class browsing (delegates to inspector + JSON formatting) ----
    bool discoverClasses() { return inspector->discoverClasses(); }
    std::string listClasses(const std::string& root = "",
                            bool namesOnly = false) const;
    std::string getClass(const std::string& name) const;
    std::string getSubclasses(const std::string& name) const;
    std::string getSuperclasses(const std::string& name) const;
    std::string getVariables(const std::string& name) const;
    std::string getInstanceVariables(const std::string& name) const;
    std::string getClassVariables(const std::string& name) const;
    std::string getCategories(const std::string& name) const;
    std::string getUsedCategories(const std::string& name) const;
    std::string getSelectors(const std::string& name) const;
    std::string getMethods(const std::string& name) const;
    std::string getMethod(const std::string& className,
                          const std::string& selector) const;
    std::string search(const std::string& text, bool ignoreCase,
                       const std::string& condition,
                       const std::string& type) const;

    /// Underlying debugger (for low-level access).
    smalldbg::Debugger* getDebugger() const { return debugger.get(); }

    /// Access the Egg VM inspector.
    egg::EggInspector* getInspector() const { return inspector.get(); }

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
