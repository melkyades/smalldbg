#include "Target.h"

#include <smalldbg/Debugger.h>

namespace vmdbg {

namespace {

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size()
        && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} // namespace

TargetKind targetKindFor(const std::string& path) {
    if (endsWith(path, ".run")) return TargetKind::Trace;
    if (endsWith(path, ".dmp")) return TargetKind::Dump;
    return TargetKind::Launch;
}

smalldbg::Status openInEngine(smalldbg::Debugger& debugger,
                              const TargetSpec& target) {
    switch (target.kind) {
    case TargetKind::Launch: return debugger.launch(target.path, target.args, target.workingDir);
    case TargetKind::Attach: return debugger.attach(target.pid);
    case TargetKind::Dump:   return debugger.openDump(target.path);
    case TargetKind::Trace:  return debugger.openTrace(target.path);
    }
    return smalldbg::Status::Error;
}

smalldbg::Debuggee debuggeeFor(TargetKind kind) {
    return kind == TargetKind::Trace ? smalldbg::Debuggee::Trace
                                     : smalldbg::Debuggee::Process;
}

} // namespace vmdbg
