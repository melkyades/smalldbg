#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>
#include <cstddef>

#include "VMSession.h"

namespace smalldbg {
    class Debugger;
    class Thread;
    class StackTrace;
    struct StackFrame;
}

namespace webside {

class Json;             // forward declaration

/// The Webside API over a VM session.
///
/// What the runtime holds is vmdbg::VMSession's to say; this turns it into
/// the documents the Webside client expects.
class WebsideSession : public vmdbg::VMSession {
public:
    // ---- state queries ----
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
    /// Where the frame's function starts, for a client that disassembles it.
    static uint64_t functionAddressOf(const smalldbg::StackFrame& frame);

    /// A target address in hex at that width, so a 32-bit target's addresses
    /// are not padded out to 16 digits.
    Json addressHex(uint64_t address) const;

    /// What the addresses in [from, to) mean in terms of the frames on this
    /// stack. Contents come from /memory; this says which frame owns a slot
    /// and what it holds. Addresses inside no frame are simply absent.
    std::string stackDescriptors(const smalldbg::StackTrace& trace, int selectedIndex,
                                 uint64_t from, int slots) const;

    // ---- green threads, as documents ----
    virtual std::string listSmalltalkFrames(int threadIndex) const = 0;
    virtual std::string getSmalltalkFrameDetail(int threadIndex, int frameIndex) const = 0;
    virtual std::string getSmalltalkFrameBindings(int threadIndex, int frameIndex) const = 0;
    /** Returns a green thread's stack slots, each placed relative to the
     *  frame `selectedFrame`. **/
    virtual std::string getSmalltalkStackContents(int threadIndex,
                                                  int selectedFrame) const = 0;
    /// Registers for one green-thread frame. A dialect whose activations are
    /// not native frames has nothing to say here.
    virtual std::string getSmalltalkFrameRegisters(int, int) const { return "[]"; }

    // ---- class browsing ----
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
    virtual std::string listBreakpoints() const = 0;

    // ---- memory ----
    virtual std::string readMemory(uint64_t address, size_t size) const = 0;

    // ---- events ----
    virtual std::string waitForEvent(int timeoutMs = 5000) = 0;

    // ---- object description ----
    virtual std::string describeObject(uint64_t handle, size_t maxDepth = 1) const = 0;

protected:
    // ---- virtual hooks for frame formatting ----
    // Dialects override these; the base builds generic native JSON.

    /// Display label for a frame (used by listFrames).
    virtual std::string buildFrameLabel(const smalldbg::StackFrame& frame) const;

    /** JSON detail for one frame; dispatches to the smalltalk/native hook
     *  based on whether the frame carries unwinder metadata. **/
    virtual std::string buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                             int index) const;
    virtual void addSmalltalkFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;
    virtual void addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;

    /// JSON bindings (locals + IP/FP/SP) for one frame; dispatches on metadata.
    virtual std::string buildFrameBindingsJson(const smalldbg::StackFrame& frame,
                                               int index) const;
    virtual std::string addSmalltalkFrameBindings(const smalldbg::StackFrame& frame) const;
    virtual std::string addNativeFrameBindings(const smalldbg::StackFrame& frame) const;

    /// Arguments of one frame as [{name, value}]. Empty where a dialect
    /// cannot tell arguments from locals, which is the base case.
    virtual std::string buildFrameArgumentsJson(const smalldbg::StackFrame& frame) const;

    /// JSON register dump for one frame (arch-aware).
    virtual std::string buildFrameRegistersJson(const smalldbg::StackFrame& frame) const;

    /// Descriptors for the slots of one frame that fall in [from, to).
    void describeFrameSlots(Json& out, const smalldbg::StackFrame& frame,
                            int frameIndex, int selectedIndex, size_t slot,
                            uint64_t from, uint64_t to) const;

    /// One descriptor per meaningful address in [from, to). The base names the
    /// slots any frame-pointer ABI has; dialects add what their own frame
    /// layout means and may read the target to describe a slot's value.
    virtual std::string buildStackDescriptorsJson(smalldbg::Debugger* dbg,
                                                  const smalldbg::StackTrace& trace,
                                                  int selectedIndex,
                                                  uint64_t from,
                                                  uint64_t to) const;
};

} // namespace webside
