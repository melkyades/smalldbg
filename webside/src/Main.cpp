#include "Main.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace webside {
namespace {

bool isNumber(const std::string& word) {
    return !word.empty() &&
           word.find_first_not_of("0123456789") == std::string::npos;
}

const char* nameOf(TargetKind kind) {
    switch (kind) {
    case TargetKind::Launch: return "launch";
    case TargetKind::Attach: return "attach";
    case TargetKind::Dump:   return "a dump";
    case TargetKind::Trace:  return "a trace";
    }
    return "that";
}

bool opens(const DialectInfo& dialect, TargetKind kind) {
    switch (kind) {
    case TargetKind::Launch: return dialect.opensLaunch;
    case TargetKind::Attach: return dialect.opensAttach;
    case TargetKind::Dump:   return dialect.opensDump;
    case TargetKind::Trace:  return dialect.opensTrace;
    }
    return false;
}

void printUsage(const char* argv0, const DialectInfo& dialect) {
    std::cerr
        << "Usage: " << argv0 << " " << dialect.targetSyntax
        << " [options] [-- target args...]\n"
        << "\n"
        << "  --port N          HTTP port (default 7000, or a bare number)\n"
        << "  --pid N           attach to a running process\n"
        << "  --workspace FILE  breakpoints, labels and symbol paths;\n"
        << "                    defaults to <target>.workspace.json for a dump"
           " or a trace\n"
        << "  --symbols PATH    extra directories to look for pdbs in\n"
        << "  --source DIR      where the target's sources are\n"
        << "  --pause-ms N      let a launched target run this long before"
           " suspending it\n"
        << "  -v, --verbose     log what the session is doing\n";
    if (!dialect.extraUsage.empty()) std::cerr << dialect.extraUsage;
}

// What the command line names besides the options an Invocation keeps.
struct Words {
    std::string target;
    std::string sourcePath;
    int pid{0};
    bool portGiven{false};
    std::vector<std::string> targetArgs;
};

// Reads the option at argv[i] and its value, leaving i on the last word read.
// Returns false, after saying why, when the option is unknown or has no value.
bool readOption(int argc, char** argv, int& i, Invocation& invocation,
                Words& words) {
    const std::string option = argv[i];
    if (option == "-v" || option == "--verbose") {
        invocation.verbose = true;
        return true;
    }
    static const std::set<std::string> valued{
        "--port", "--pid", "--workspace", "--symbols", "--source",
        "--pause-ms"};
    if (valued.count(option) == 0) {
        std::cerr << "Unknown option: " << option << "\n\n";
        return false;
    }
    if (i + 1 >= argc) {
        std::cerr << "Missing value for " << option << "\n\n";
        return false;
    }
    const std::string value = argv[++i];
    if (option == "--port") {
        invocation.port = std::atoi(value.c_str());
        words.portGiven = true;
    } else if (option == "--pid") {
        words.pid = std::atoi(value.c_str());
    } else if (option == "--workspace") {
        invocation.configPath = value;
    } else if (option == "--symbols") {
        invocation.symbolPath = value;
    } else if (option == "--source") {
        words.sourcePath = value;
    } else {
        invocation.pauseMs = std::atoi(value.c_str());
    }
    return true;
}

// Reads every word of the command line. A word spelled like an option is
// never taken as the target, and a bare number before the target is the port.
// Returns false when an option is wrong.
bool readWords(int argc, char** argv, Invocation& invocation, Words& words) {
    for (int i = 1; i < argc; i++) {
        const std::string word = argv[i];
        if (word == "--") {
            for (++i; i < argc; i++) words.targetArgs.push_back(argv[i]);
            break;
        }
        if (word == "-v" || word.rfind("--", 0) == 0) {
            if (!readOption(argc, argv, i, invocation, words)) return false;
        } else if (!words.portGiven && words.target.empty()
                   && isNumber(word)) {
            invocation.port = std::atoi(word.c_str());
            words.portGiven = true;
        } else if (words.target.empty()) {
            words.target = word;
        } else {
            words.targetArgs.push_back(word);
        }
    }
    return true;
}

} // namespace

Invocation parseCommandLine(int argc, char** argv, const DialectInfo& dialect) {
    Invocation invocation;
    Words words;
    if (!readWords(argc, argv, invocation, words)) {
        printUsage(argv[0], dialect);
        return invocation;
    }

    // An attach names no file, so it is the one target that stands without one.
    if (words.target.empty() && words.pid == 0) {
        printUsage(argv[0], dialect);
        return invocation;
    }

    TargetKind kind = words.pid != 0 ? TargetKind::Attach
                                     : targetKindFor(words.target);
    if (!opens(dialect, kind)) {
        std::cerr << dialect.name << " cannot open " << nameOf(kind) << "\n\n";
        printUsage(argv[0], dialect);
        return invocation;
    }

    // A trace or a dump is a fixed file, so its workspace is kept beside it
    // unless the developer names another.
    if (invocation.configPath.empty()
        && (kind == TargetKind::Trace || kind == TargetKind::Dump))
        invocation.configPath = words.target + ".workspace.json";

    invocation.spec.kind = kind;
    invocation.spec.path = words.target;
    invocation.spec.pid = words.pid;
    invocation.spec.args = words.targetArgs;
    invocation.spec.sourcePath = words.sourcePath;
    invocation.ok = true;
    return invocation;
}

bool openTarget(Workspace& workspace, const Invocation& invocation,
                const DialectInfo& dialect) {
    // Each line carries the milliseconds since startup, so that a slow phase
    // can be told from a slow line.
    const std::string prefix = dialect.name;
    workspace.setLogCallback([prefix](const std::string& message) {
        static const auto start = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        std::fprintf(stderr, "[%s %6lld] %s\n", prefix.c_str(),
                     static_cast<long long>(elapsed), message.c_str());
    });
    workspace.setVerboseLogging(invocation.verbose);
    if (invocation.pauseMs >= 0) workspace.setStartupPause(invocation.pauseMs);

    // The command line overrides what the workspace file holds.
    if (!invocation.configPath.empty()) workspace.load(invocation.configPath);
    if (!invocation.symbolPath.empty())
        workspace.setSymbolSearchPath(invocation.symbolPath);

    TargetSpec spec = workspace.target();
    spec.kind = invocation.spec.kind;
    spec.pid = invocation.spec.pid;
    if (!invocation.spec.path.empty()) spec.path = invocation.spec.path;
    if (!invocation.spec.args.empty()) spec.args = invocation.spec.args;
    if (!invocation.spec.sourcePath.empty())
        spec.sourcePath = invocation.spec.sourcePath;

    if (workspace.open(spec)) return true;

    std::cerr << "Failed to open " << dialect.name << " target: "
              << (spec.pid != 0 ? "pid " + std::to_string(spec.pid) : spec.path)
              << std::endl;
    return false;
}

} // namespace webside
