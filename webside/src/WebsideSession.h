#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace smalldbg {
    class Debugger;
    class Thread;
    class StackTrace;
    struct StackFrame;
}

namespace webside {

class Json;             // forward declaration
class WebsideInspector; // forward declaration

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

    // ---- frame API ----
    // These take real debugger objects; the WebsideServer layer resolves the
    // thread and frame from the request, then calls these. A frame is a VM
    // (Smalltalk) frame when frame.metadata != nullptr, native otherwise.
    std::string listFrames(smalldbg::Thread& thread, size_t maxFrames = 256) const;
    std::string getFrameDetail(smalldbg::StackTrace& trace,
                               const smalldbg::StackFrame& frame, int index) const;
    std::string getFrameBindings(smalldbg::StackTrace& trace,
                                 const smalldbg::StackFrame& frame, int index) const;
    std::string getFrameRegisters(const smalldbg::StackFrame& frame) const;
    std::string getFrameStack(const smalldbg::StackTrace& trace, int index) const;

    // ---- green threads (Smalltalk-level) ----
    virtual void refreshGreenThreads() = 0;
    virtual int greenThreadCount() const = 0;
    virtual std::string getGreenThreadName(int threadIndex) const = 0;
    virtual std::string listSmalltalkFrames(int threadIndex) const = 0;
    virtual std::string getSmalltalkFrameDetail(int threadIndex, int frameIndex) const = 0;
    virtual std::string getSmalltalkFrameBindings(int threadIndex, int frameIndex) const = 0;
    virtual std::string getSmalltalkStackContents(int threadIndex) const = 0;

    // ---- class browsing ----
    virtual bool discoverClasses() = 0;
    virtual std::string listClasses(const std::string& root = "",
                                    bool namesOnly = false,
                                    bool tree = false,
                                    int depth = -1) const = 0;
    virtual std::string getClass(const std::string& name) const = 0;
    virtual std::string getSubclasses(const std::string& name) const = 0;
    virtual std::string getSuperclasses(const std::string& name) const = 0;
    virtual std::string getVariables(const std::string& name) const = 0;
    virtual std::string getInstanceVariables(const std::string& name) const = 0;
    virtual std::string getClassVariables(const std::string& name) const = 0;
    virtual std::string getCategories(const std::string& name) const = 0;
    virtual std::string getUsedCategories(const std::string& name) const = 0;
    virtual std::string getSelectors(const std::string& name) const = 0;
    virtual std::string getMethods(const std::string& name) const = 0;
    virtual std::string getMethod(const std::string& className,
                                  const std::string& selector) const = 0;
    virtual std::string search(const std::string& text, bool ignoreCase,
                               const std::string& condition,
                               const std::string& type) const = 0;

    // ---- breakpoints ----
    virtual bool setBreakpoint(uint64_t address, const std::string& name = "") = 0;
    virtual bool clearBreakpoint(uint64_t address) = 0;
    virtual std::string listBreakpoints() const = 0;

    // ---- memory ----
    virtual std::string readMemory(uint64_t address, size_t size) const = 0;

    // ---- events ----
    virtual std::string waitForEvent(int timeoutMs = 5000) = 0;

    // ---- object description ----
    virtual std::string describeObject(uint64_t handle, size_t maxDepth = 1) const = 0;

    // ---- underlying debugger / VM inspector ----
    virtual smalldbg::Debugger* getDebugger() const = 0;
    virtual WebsideInspector* getInspector() const = 0;

    // ---- thread helpers ----
    std::shared_ptr<smalldbg::Thread> resolveThread(uint64_t threadId) const;
    std::shared_ptr<smalldbg::Thread> primaryThread() const;

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

    /// JSON bindings (locals + IP/FP/SP) for one frame; dispatches on metadata.
    virtual std::string buildFrameBindingsJson(const smalldbg::StackFrame& frame,
                                               int index) const;
    virtual std::string addSmalltalkFrameBindings(const smalldbg::StackFrame& frame) const;
    virtual std::string addNativeFrameBindings(const smalldbg::StackFrame& frame) const;

    /// JSON register dump for one frame (arch-aware).
    virtual std::string buildFrameRegistersJson(const smalldbg::StackFrame& frame) const;

    /// JSON view of the raw stack memory around a frame (reads target memory).
    virtual std::string buildFrameStackJson(smalldbg::Debugger* dbg,
                                            const smalldbg::StackTrace& trace,
                                            int rawIndex) const;
};

} // namespace webside
