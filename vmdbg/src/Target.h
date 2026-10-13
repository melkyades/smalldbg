#pragma once

#include <smalldbg/Types.h>

#include <string>
#include <vector>

namespace smalldbg { class Debugger; }

namespace vmdbg {

/** How the program to debug is reached. **/
enum class TargetKind { Launch, Attach, Trace, Dump };

/** Which program to debug and how to reach it. It stays valid after a session
 *  ends, so opening it again starts the next one. **/
struct TargetSpec {
    TargetKind kind{TargetKind::Launch};
    std::string path;                 // executable, .run trace or .dmp dump
    std::vector<std::string> args;    // launch only
    std::string workingDir;           // launch only; empty for the backend's default
    int pid{0};                       // attach only
    std::string sourcePath;           // where the dialect's sources live
};

/** Returns true for a target that is a file on disk rather than a running
 *  program. **/
inline bool isRecordedTarget(TargetKind kind) {
    return kind == TargetKind::Dump || kind == TargetKind::Trace;
}

/** Returns the kind a path names: a .run trace, a .dmp dump, or otherwise an
 *  executable to launch. **/
TargetKind targetKindFor(const std::string& path);

/** Opens the target in the debugger with the call its kind needs, and
 *  returns what that call returned. **/
smalldbg::Status openInEngine(smalldbg::Debugger& debugger,
                              const TargetSpec& target);

/** Returns what a Debugger that opens this kind of target is built for. **/
smalldbg::Debuggee debuggeeFor(TargetKind kind);

} // namespace vmdbg
