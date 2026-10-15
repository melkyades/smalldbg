#include "WebsideSession.h"
#include "Json.h"
#include "SourceExcerpt.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/DisassemblyAnnotator.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"

#include <algorithm>
#include <cstring>

namespace webside {

std::unique_ptr<smalldbg::AnnotationSource> WebsideSession::annotationSource() const {
    return std::make_unique<smalldbg::SymbolAnnotationSource>(debugger());
}

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
    // The arguments a frame's line shows come with its details.
    for (size_t i = 0; i < trace->getFrameCount(); i++)
        trace->resolveFrameDetails(i, &debugger());
    return listFrames(*trace);
}

std::string WebsideSession::listFrames(const smalldbg::StackTrace& trace) const {
    const auto& frames = trace.getFrames();
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
    return buildStackDescriptorsJson(trace, selectedIndex, from, to);
}

// From the innermost frame's sp to the outermost frame's return address.
std::string WebsideSession::stackDescriptors(const smalldbg::StackTrace& trace,
                                             int selectedIndex) const {
    uint64_t from = UINT64_MAX;
    uint64_t to = 0;
    for (const auto& frame : trace.getFrames()) {
        if (frame->inlined) continue;
        if (frame->sp() != 0) from = std::min(from, frame->sp());
        if (frame->fp() != 0) to = std::max(to, frame->fp() + 2 * pointerSize());
    }
    if (to <= from) return "[]";
    return buildStackDescriptorsJson(trace, selectedIndex, from, to);
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
        .set("hasSource", false)
        .set("interval", Json::object().set("start", 0).set("end", 0));

    if (frame.metadata)
        addSmalltalkFrameDetail(j, frame);
    else
        addNativeFrameDetail(j, frame);
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

// The symbols say where a native function's source is, and the function that
// holds the frame's line is shown with that line marked.
void WebsideSession::addNativeFrameDetail(Json& j, const smalldbg::StackFrame& frame) const {
    std::string modName = frame.moduleName.empty() ? "<native>" : frame.moduleName;
    j.set("class", Json::object()
        .set("name", modName)
        .set("definition", "")
        .set("category", "native"));

    std::string source = frame.functionName.empty()
        ? std::string("<native code>") : frame.functionName + " (native code)";
    if (!frame.sourceFile.empty() && frame.sourceLine > 0) {
        if (auto excerpt = functionAround(frame.sourceFile, frame.sourceLine)) {
            source = excerpt->text;
            j.set("hasSource", true);
            j.set("interval", Json::object()
                .set("start", excerpt->lineStart)
                .set("end", excerpt->lineStart + excerpt->lineLength));
        } else {
            source = frame.functionName + " (source file not accessible: "
                   + frame.sourceFile + ":" + std::to_string(frame.sourceLine) + ")";
        }
    }
    j.set("method", Json::object()
        .set("selector", frame.functionName)
        .set("methodClass", frame.moduleName)
        .set("category", "native")
        .set("source", source));
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

// A value the symbols format, such as a string's text, is its print string.
static Json argumentJson(const smalldbg::LocalVariable& variable) {
    auto entry = Json::object()
        .set("name", variable.name)
        .set("type", variable.typeName);
    auto value = variable.getValue();
    if (!value) entry.set("value", variable.valueText);
    else if (variable.size <= 4) entry.set("value", Json::hex(static_cast<uint32_t>(*value)));
    else entry.set("value", Json::hex(*value));
    if (!variable.valueText.empty()) entry.set("printString", variable.valueText);
    return entry;
}

std::string WebsideSession::buildFrameArgumentsJson(const smalldbg::StackFrame& frame) const {
    auto arr = Json::array();
    for (const auto& variable : frame.localVariables)
        if (variable.isArgument) arr.add(argumentJson(variable));
    return arr.dump();
}

std::string WebsideSession::buildFrameRegistersJson(const smalldbg::StackFrame& frame) const {
    using Role = smalldbg::RegisterValue::Role;
    auto arr = Json::array();
    for (const auto& reg : frame.registerValues()) {
        auto entry = Json::object().set("name", reg.name);
        if (!reg.value) {
            arr.add(std::move(entry.set("value", nullptr)));
            continue;
        }
        entry.set("value", addressHex(*reg.value));
        if (reg.role == Role::Flags)
            entry.set("description", frame.registers.arch->describeFlags(*reg.value));
        else
            describeRegister(entry, frame, reg);
        arr.add(std::move(entry));
    }
    return arr.dump();
}

void WebsideSession::describeRegister(Json& entry, const smalldbg::StackFrame& frame,
                                      const smalldbg::RegisterValue& reg) const {
    if (reg.role == smalldbg::RegisterValue::Role::Ip)
        entry.set("printString", buildFrameLabel(frame));
}

namespace {

// Returns the frame that frame `index`, counted from 1, stands for: an
// inlined frame's slots are those of the frame it was inlined into.
int physicalIndex(const std::vector<std::unique_ptr<smalldbg::StackFrame>>& frames,
                  int index) {
    size_t at = index < 1 ? 0 : static_cast<size_t>(index - 1);
    while (at < frames.size() && frames[at]->inlined) ++at;
    return static_cast<int>(at + 1);
}

// Returns the role the slot at `address` has in `frame`, or null when it has
// none. On ARM64 the frame record is often at the bottom of the frame, so fp
// and sp are the same slot; it is the sp then, as the return address next to
// it already shows where the frame record is.
const char* abiRole(const smalldbg::StackFrame& frame, uint64_t address, size_t slot) {
    if (address == frame.fp() + slot) return "retAddr";
    if (address == frame.sp()) return "sp";
    if (address == frame.fp()) return "fp";
    return nullptr;
}

} // namespace

// A frame owns every slot from its sp up to its return address, so that a
// client grouping slots by frame finds no gaps. A slot two frames claim is
// the inner one's.
std::string WebsideSession::buildStackDescriptorsJson(const smalldbg::StackTrace& trace,
                                                      int selectedIndex,
                                                      uint64_t from, uint64_t to) const {
    const size_t slot = pointerSize();
    from -= from % slot;
    to = std::min(to, from + 0x10000);  // at most 64 KB
    if (to <= from) return "[]";
    std::vector<uint8_t> words(to - from);
    if (debugger().readMemory(from, words.data(), words.size()) != smalldbg::Status::Ok)
        return "[]";

    const auto& frames = trace.getFrames();
    const int selected = physicalIndex(frames, selectedIndex);
    auto arr = Json::array();
    for (uint64_t address = from; address + slot <= to; address += slot) {
        const uint8_t* bytes = &words[address - from];
        const uint64_t value = slot == 4 ? *reinterpret_cast<const uint32_t*>(bytes)
                                         : *reinterpret_cast<const uint64_t*>(bytes);
        auto entry = Json::object().set("address", addressHex(address));
        const smalldbg::StackFrame* owner = nullptr;
        for (size_t i = 0; i < frames.size() && !owner; ++i) {
            const smalldbg::StackFrame& frame = *frames[i];
            if (frame.inlined) continue;
            const char* role = abiRole(frame, address, slot);
            // A frame without a frame pointer, such as a leaf, owns only the
            // slots with a role.
            bool extentKnown = frame.fp() + slot > frame.sp();
            bool owned = extentKnown && address >= frame.sp() && address <= frame.fp() + slot;
            if (!role && !owned) continue;

            owner = &frame;
            const int index = static_cast<int>(i + 1);
            entry.set("frameIndex", index)
                 .set("frameRel", index < selected ? -1 : index == selected ? 0 : 1);
            if (role) entry.set("role", role);
            if (role && std::string(role) == "retAddr")
                addReturnLabel(entry, frames, i, value);
        }
        describeSlot(entry, owner, address, value);
        if (entry.size() > 1) arr.add(std::move(entry));
    }
    return arr.dump();
}

// A return address is labelled with where it returns to in the caller: the
// next frame neither inlined nor sharing the frame pointer, as a leaf does.
void WebsideSession::addReturnLabel(
    Json& entry, const std::vector<std::unique_ptr<smalldbg::StackFrame>>& frames,
    size_t index, uint64_t value) const {
    size_t caller = index + 1;
    while (caller < frames.size()
           && (frames[caller]->inlined || frames[caller]->fp() == frames[index]->fp()))
        ++caller;
    if (caller >= frames.size()) return;
    const uint64_t start = functionAddressOf(*frames[caller]);
    if (start == 0 || value < start) return;
    entry.set("printString", buildFrameLabel(*frames[caller]) + "+"
                             + std::to_string(value - start));
}

void WebsideSession::describeSlot(Json& /*entry*/, const smalldbg::StackFrame* /*frame*/,
                                  uint64_t /*address*/, uint64_t /*value*/) const {}

} // namespace webside
