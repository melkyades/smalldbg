#include "WebsideSession.h"
#include "Json.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"

#include <algorithm>
#include <cstring>

namespace webside {

Json WebsideSession::addressHex(uint64_t address) const {
    return pointerSize() <= 4 ? Json::hex(static_cast<uint32_t>(address))
                              : Json::hex(address);
}

// =========================================================================
// Public frame API — takes real debugger objects, delegates formatting to hooks
// =========================================================================

std::string WebsideSession::listFrames(smalldbg::Thread& thread, size_t maxFrames) const {
    prepareFrames();
    auto* trace = thread.getStackTrace(std::max(maxFrames, size_t(64)));
    if (!trace) return "[]";

    const auto& frames = trace->getFrames();
    auto arr = Json::array();
    for (size_t i = 0; i < frames.size(); i++) {
        const smalldbg::StackFrame& frame = *frames[i];
        auto entry = Json::object()
            .set("index", static_cast<int>(i + 1))
            .set("label", buildFrameLabel(frame))
            .set("ip", addressHex(frame.ip()))
            .set("functionOffset", static_cast<int64_t>(frame.functionOffset))
            .set("functionAddress", addressHex(functionAddressOf(frame)));

        // Where the frame sits, so that a client can show it and go to it
        // without asking for the frame's detail.
        entry.set("framePointer", addressHex(frame.fp()))
             .set("stackPointer", addressHex(frame.sp()));
        if (!frame.moduleName.empty()) entry.set("module", frame.moduleName);

        if (frame.inlined) entry.set("inlined", true);
        std::string args = buildFrameArgumentsJson(frame);
        if (args != "[]") entry.set("arguments", Json::parse(args));
        arr.add(std::move(entry));
    }
    return arr.dump();
}

std::string WebsideSession::getFrameDetail(smalldbg::StackTrace& trace,
                                           const smalldbg::StackFrame& frame, int index) const {
    trace.resolveFrameDetails(index - 1, &debugger());
    return buildFrameDetailJson(frame, index);
}

std::string WebsideSession::getFrameBindings(smalldbg::StackTrace& trace,
                                             const smalldbg::StackFrame& frame, int index) const {
    trace.resolveFrameDetails(index - 1, &debugger());
    return buildFrameBindingsJson(frame, index);
}

std::string WebsideSession::getFrameRegisters(const smalldbg::StackFrame& frame) const {
    return buildFrameRegistersJson(frame);
}

std::string WebsideSession::stackDescriptors(const smalldbg::StackTrace& trace,
                                             int selectedIndex,
                                             uint64_t from, int slots) const {
    uint64_t to = from + static_cast<uint64_t>(slots) * pointerSize();
    return buildStackDescriptorsJson(&debugger(), trace, selectedIndex, from, to);
}

// =========================================================================
// Virtual frame-formatting hooks — generic native behavior. Dialect sessions
// override these to enrich frames with VM-specific information.
// =========================================================================

std::string WebsideSession::buildFrameLabel(const smalldbg::StackFrame& frame) const {
    if (!frame.moduleName.empty() && !frame.functionName.empty())
        return frame.moduleName + "!" + frame.functionName;
    if (!frame.functionName.empty())
        return frame.functionName;
    return "<unknown>";
}

// Not always ip minus functionOffset: a frame parked in a runtime stub has an
// ip outside the code of the function that owns it.
uint64_t WebsideSession::functionAddressOf(const smalldbg::StackFrame& frame) {
    return frame.functionStart ? frame.functionStart
                               : frame.ip() - frame.functionOffset;
}

std::string WebsideSession::buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                                 int index) const {
    auto j = Json::object()
        .set("index", index)
        .set("label", buildFrameLabel(frame))
        .set("ip", addressHex(frame.ip()))
        .set("functionAddress", addressHex(functionAddressOf(frame)))
        .set("functionOffset", static_cast<int64_t>(frame.functionOffset))
        .set("inlined", frame.inlined)
        .set("hasSource", false);

    if (frame.metadata)
        addSmalltalkFrameDetail(j, frame);
    else
        addNativeFrameDetail(j, frame);

    j.set("interval", Json::object().set("start", 0).set("end", 0));
    return j.dump();
}

void WebsideSession::addSmalltalkFrameDetail(Json& j, const smalldbg::StackFrame& frame) const {
    j.set("class", Json::object()
        .set("name", frame.moduleName)
        .set("definition", "")
        .set("category", "vm"));
    j.set("method", Json::object()
        .set("selector", frame.functionName)
        .set("methodClass", frame.moduleName)
        .set("category", "vm")
        .set("source", frame.functionName));
}

void WebsideSession::addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const {
    std::string modName = frame.moduleName.empty() ? "<native>" : frame.moduleName;
    j.set("class", Json::object()
        .set("name", modName)
        .set("definition", "")
        .set("category", "native"));
    j.set("method", Json::object()
        .set("selector", frame.functionName)
        .set("methodClass", frame.moduleName)
        .set("category", "native")
        .set("source", frame.functionName.empty()
            ? std::string("<native code>")
            : frame.functionName + " (native code)"));
}

std::string WebsideSession::buildFrameBindingsJson(const smalldbg::StackFrame& frame,
                                                   int /*index*/) const {
    if (frame.metadata)
        return addSmalltalkFrameBindings(frame);
    return addNativeFrameBindings(frame);
}

std::string WebsideSession::addSmalltalkFrameBindings(const smalldbg::StackFrame& frame) const {
    return addNativeFrameBindings(frame);
}

std::string WebsideSession::addNativeFrameBindings(const smalldbg::StackFrame& frame) const {
    auto arr = Json::array();
    arr.add(Json::object().set("name", "IP").set("value", Json::hex(frame.ip())));
    arr.add(Json::object().set("name", "FP").set("value", Json::hex(frame.fp())));
    arr.add(Json::object().set("name", "SP").set("value", Json::hex(frame.sp())));
    for (const auto& lv : frame.localVariables) {
        if (lv.name.size() >= 2 && lv.name[0] == '_' && lv.name[1] == '_')
            continue;
        auto binding = Json::object()
            .set("name", lv.name)
            .set("type", lv.typeName)
            .set("location", lv.getLocationString());
        auto val = lv.getValue();
        if (val.has_value())
            binding.set("value", Json::hex(val.value()));
        else
            binding.set("value", "?");
        arr.add(std::move(binding));
    }
    return arr.dump();
}

std::string WebsideSession::buildFrameArgumentsJson(
    const smalldbg::StackFrame& /*frame*/) const {
    return "[]";
}

std::string WebsideSession::buildFrameRegistersJson(const smalldbg::StackFrame& frame) const {
    const auto& regs = frame.registers;
    auto arr = Json::array();
    auto add = [&](const char* name, uint64_t v, bool isFlags = false) {
        auto entry = Json::object().set("name", name).set("value", Json::hex(v));
        if (isFlags) entry.set("description", regs.arch->describeFlags(v));
        arr.add(std::move(entry));
    };
    if (regs.arch == smalldbg::X86::instance()) {
        const auto& r = regs.x86;
        add("eip", r.eip); add("esp", r.esp); add("ebp", r.ebp);
        add("eax", r.eax); add("ebx", r.ebx); add("ecx", r.ecx);
        add("edx", r.edx); add("esi", r.esi); add("edi", r.edi);
        add("eflags", r.eflags, true);
    } else if (regs.arch == smalldbg::X64::instance()) {
        const auto& r = regs.x64;
        add("rip", r.rip); add("rsp", r.rsp); add("rbp", r.rbp);
        add("rax", r.rax); add("rbx", r.rbx); add("rcx", r.rcx);
        add("rdx", r.rdx); add("rsi", r.rsi); add("rdi", r.rdi);
        add("r8", r.r8); add("r9", r.r9); add("r10", r.r10);
        add("r11", r.r11); add("r12", r.r12); add("r13", r.r13);
        add("r14", r.r14); add("r15", r.r15);
        add("rflags", r.rflags, true);
    } else {
        add("ip", regs.ip()); add("fp", regs.fp()); add("sp", regs.sp());
    }
    return arr.dump();
}

// Every slot a frame owns is described, not only the ones with a role: a
// client groups slots into frames by frameIndex, and a gap would split one.
void WebsideSession::describeFrameSlots(Json& out, const smalldbg::StackFrame& frame,
                                        int frameIndex, int selectedIndex, size_t slot,
                                        uint64_t from, uint64_t to) const {
    int rel = frameIndex < selectedIndex ? -1 : frameIndex == selectedIndex ? 0 : 1;
    uint64_t returnAddress = frame.fp() + slot;
    // A frame without a frame pointer, such as a leaf, has no known extent,
    // so only its slots with a role are described.
    bool extentKnown = returnAddress > frame.sp();

    // The slots are walked from `from`, so that they line up with the ones
    // the client read from /memory.
    for (uint64_t address = from; address < to; address += slot) {
        const char* role = address == returnAddress ? "retAddr"
                         : address == frame.fp()    ? "fp"
                         : address == frame.sp()    ? "sp"
                                                    : nullptr;
        bool owned = extentKnown && address >= frame.sp() && address <= returnAddress;
        if (!role && !owned) continue;

        auto entry = Json::object()
            .set("address", addressHex(address))
            .set("frameIndex", frameIndex)
            .set("frameRel", rel);
        if (role) entry.set("role", role);
        out.add(std::move(entry));
    }
}

std::string WebsideSession::buildStackDescriptorsJson(smalldbg::Debugger* /*dbg*/,
                                                      const smalldbg::StackTrace& trace,
                                                      int selectedIndex,
                                                      uint64_t from,
                                                      uint64_t to) const {
    const auto& frames = trace.getFrames();
    size_t slot = pointerSize();
    auto arr = Json::array();

    for (size_t i = 0; i < frames.size(); i++)
        describeFrameSlots(arr, *frames[i], static_cast<int>(i + 1), selectedIndex,
                           slot, from, to);

    return arr.dump();
}

} // namespace webside
