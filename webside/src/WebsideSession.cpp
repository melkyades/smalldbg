#include "WebsideSession.h"
#include "Json.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Arch.h"

namespace webside {

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

std::string WebsideSession::buildFrameDetailJson(const smalldbg::StackFrame& frame,
                                                 int index) const {
    auto j = Json::object()
        .set("index", index)
        .set("label", buildFrameLabel(frame));

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
            .set("type", lv.typeName);
        auto val = lv.getValue();
        if (val.has_value())
            binding.set("value", Json::hex(val.value()));
        else
            binding.set("value", "?");
        arr.add(std::move(binding));
    }
    return arr.dump();
}

std::string WebsideSession::buildFrameRegistersJson(const smalldbg::StackFrame& frame) const {
    const auto& regs = frame.registers;
    auto arr = Json::array();
    auto add = [&](const char* name, uint64_t v) {
        arr.add(Json::object().set("name", name).set("value", Json::hex(v)));
    };
    if (regs.arch == smalldbg::X86::instance()) {
        const auto& r = regs.x86;
        add("eip", r.eip); add("esp", r.esp); add("ebp", r.ebp);
        add("eax", r.eax); add("ebx", r.ebx); add("ecx", r.ecx);
        add("edx", r.edx); add("esi", r.esi); add("edi", r.edi);
        add("eflags", r.eflags);
    } else if (regs.arch == smalldbg::X64::instance()) {
        const auto& r = regs.x64;
        add("rip", r.rip); add("rsp", r.rsp); add("rbp", r.rbp);
        add("rax", r.rax); add("rbx", r.rbx); add("rcx", r.rcx);
        add("rdx", r.rdx); add("rsi", r.rsi); add("rdi", r.rdi);
        add("r8", r.r8); add("r9", r.r9); add("r10", r.r10);
        add("r11", r.r11); add("r12", r.r12); add("r13", r.r13);
        add("r14", r.r14); add("r15", r.r15);
        add("rflags", r.rflags);
    } else {
        add("ip", regs.ip()); add("fp", regs.fp()); add("sp", regs.sp());
    }
    return arr.dump();
}

} // namespace webside
