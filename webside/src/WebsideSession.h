#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>
#include <cstddef>

#include "VMSession.h"

namespace smalldbg {
    class AnnotationSource;
    class Debugger;
    class Thread;
    class StackTrace;
    struct StackFrame;
    struct RegisterValue;
}

namespace vmdbg { class Json; }

namespace webside {

using vmdbg::Json;

/** A WebsideSession answers the Webside API for one VM session, in the
 *  shapes the Webside client expects. The VM's state comes from
 *  vmdbg::VMSession; a dialect's subclass describes its own frames, classes
 *  and objects. **/
class WebsideSession : public vmdbg::VMSession {
public:
    // ---- frame API ----
    // These take real debugger objects; the WebsideServer layer resolves the
    // thread and frame from the request, then calls these. A frame is a VM
    // (Smalltalk) frame when frame.metadata != nullptr, native otherwise.
    std::string listFrames(smalldbg::Thread& thread, size_t maxFrames = 256) const;
    std::string listFrames(const smalldbg::StackTrace& trace) const;
    std::string getFrameDetail(smalldbg::StackTrace& trace,
                               const smalldbg::StackFrame& frame, int index) const;
    std::string getFrameBindings(smalldbg::StackTrace& trace,
                                 const smalldbg::StackFrame& frame, int index) const;
    std::string getFrameRegisters(const smalldbg::StackFrame& frame) const;
    /** Returns where the frame's function starts, for disassembling it. **/
    static uint64_t functionAddressOf(const smalldbg::StackFrame& frame);

    /** Returns `address` in hex at the target's width, so a 32-bit target's
     *  addresses are not padded to 16 digits. **/
    Json addressHex(uint64_t address) const;

    /** Returns which frame owns each of the `slots` slots from `from`, and
     *  what it holds. Slots inside no frame are left out. **/
    std::string stackDescriptors(const smalldbg::StackTrace& trace, int selectedIndex,
                                 uint64_t from, int slots) const;
    /** Returns the descriptors of every slot of the frames of `trace`. **/
    std::string stackDescriptors(const smalldbg::StackTrace& trace,
                                 int selectedIndex) const;

    /** Returns the frames of a green thread as a trace, which the frame
     *  routes answer the way they do a native thread's. Returns null for a
     *  green thread whose frames are only described by the documents below. **/
    virtual smalldbg::StackTrace* greenStack(int /*threadIndex*/) const { return nullptr; }

    // ---- green threads, as documents ----
    virtual std::string listSmalltalkFrames(int threadIndex) const = 0;
    virtual std::string getSmalltalkFrameDetail(int threadIndex, int frameIndex) const = 0;
    virtual std::string getSmalltalkFrameBindings(int threadIndex, int frameIndex) const = 0;
    /** Returns a green thread's stack slots, each placed relative to the
     *  frame `selectedFrame`. **/
    virtual std::string getSmalltalkStackContents(int threadIndex,
                                                  int selectedFrame) const = 0;
    /** Returns the registers of one green-thread frame. The base returns
     *  none. **/
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

    // ---- listings ----
    /** Returns what names the addresses a listing refers to. The base names
     *  them by native symbol. **/
    virtual std::unique_ptr<smalldbg::AnnotationSource> annotationSource() const;

    /** Returns one line saying what a layout the VM defined holds, such as an
     *  object header's size and flags, read from `bytes`; or an empty text,
     *  as the base does, to show its bytes instead. **/
    virtual std::string layoutText(const vmdbg::MemTypeRange& /*range*/,
                                   const std::vector<uint8_t>& /*bytes*/) const {
        return {};
    }

    // ---- object description ----
    /** Returns the object at `oop` for /inspect, with up to `maxSlots` of its
     *  slots from `firstSlot`. **/
    virtual std::string describeObject(uint64_t oop, int firstSlot,
                                       int maxSlots) const = 0;

protected:
    // ---- virtual hooks for frame formatting ----
    // Dialects override these; the base builds generic native JSON.

    /** Returns the label listFrames shows for `frame`. **/
    virtual std::string buildFrameLabel(const smalldbg::StackFrame& frame) const;

    /** JSON detail for one frame; dispatches to the smalltalk/native hook
     *  based on whether the frame carries unwinder metadata. **/
    virtual std::string buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                             int index) const;
    virtual void addSmalltalkFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;
    virtual void addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const;

    /** Returns the locals and IP, FP and SP of `frame` as JSON. **/
    virtual std::string buildFrameBindingsJson(const smalldbg::StackFrame& frame,
                                               int index) const;
    virtual std::string addSmalltalkFrameBindings(const smalldbg::StackFrame& frame) const;
    virtual std::string addNativeFrameBindings(const smalldbg::StackFrame& frame) const;

    /** Returns the frame's arguments as [{name, value}]. The base cannot tell
     *  arguments from locals and returns none. **/
    virtual std::string buildFrameArgumentsJson(const smalldbg::StackFrame& frame) const;

    /** Returns the registers of `frame` as JSON, with a null value for each
     *  one the frame does not know. **/
    std::string buildFrameRegistersJson(const smalldbg::StackFrame& frame) const;

    /** Adds to `entry` what the value of a register of `frame` is. The base
     *  names the code the ip is in. **/
    virtual void describeRegister(Json& entry, const smalldbg::StackFrame& frame,
                                  const smalldbg::RegisterValue& reg) const;

    /** Returns a descriptor for each slot in [from, to) that a frame of
     *  `trace` owns or that describeSlot says something about: the frame it
     *  belongs to, where that frame is from the one selected, and its role. **/
    std::string buildStackDescriptorsJson(const smalldbg::StackTrace& trace,
                                          int selectedIndex, uint64_t from,
                                          uint64_t to) const;

    /** Adds to `entry` what the slot at `address`, which holds `value`, is
     *  to `frame`, which is null for a slot no frame owns. The base adds
     *  nothing. **/
    virtual void describeSlot(Json& entry, const smalldbg::StackFrame* frame,
                              uint64_t address, uint64_t value) const;

private:
    void addReturnLabel(Json& entry,
                        const std::vector<std::unique_ptr<smalldbg::StackFrame>>& frames,
                        size_t index, uint64_t value) const;
};

} // namespace webside
