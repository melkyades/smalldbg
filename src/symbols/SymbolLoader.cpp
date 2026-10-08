#include "smalldbg/symbols/SymbolLoader.h"
#include "smalldbg/Debugger.h"

#include <algorithm>
#include <cctype>

namespace smalldbg {

namespace {

#ifdef _WIN32
constexpr char pathSeparator = ';';
#else
constexpr char pathSeparator = ':';
#endif

std::vector<std::string> split(const std::string& path) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= path.size()) {
        size_t end = path.find(pathSeparator, start);
        if (end == std::string::npos) end = path.size();
        if (end > start) parts.push_back(path.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

std::string joined(const std::vector<std::string>& parts) {
    std::string all;
    for (const auto& part : parts) {
        if (!all.empty()) all += pathSeparator;
        all += part;
    }
    return all;
}

std::string directoryOf(const std::string& path) {
    auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}

// A module the operating system ships, whose symbols are not worth reporting.
bool isSystemModule(const std::string& imagePath) {
    std::string lower = imagePath;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower.find("\\windows\\") != std::string::npos
        || lower.find("/windows/") != std::string::npos
        || lower.find("/usr/lib/") != std::string::npos;
}

// A module nothing has asked about yet reads as "(deferred)", not "(none)",
// which would say a symbol file was looked for and not found.
std::string briefly(const ModuleInfo& module) {
    std::string state = module.symbolFile.empty()
        ? "(" + (module.symbolType.empty() ? std::string("none")
                                           : module.symbolType) + ")"
        : module.symbolFile;
    return "symbols: " + module.shortName + " <- " + state;
}

std::string atLength(const ModuleInfo& module) {
    std::string line = "symbols: " + module.shortName
                     + " type=" + (module.symbolType.empty() ? "?"
                                                             : module.symbolType);
    if (!module.symbolFile.empty()) line += " file=" + module.symbolFile;
    if (!module.path.empty()) line += " image=" + module.path;
    return line;
}

} // namespace

SymbolLoader::SymbolLoader(Debugger& debugger, LogSink logSink)
    : debug(debugger), sink(std::move(logSink)) {}

void SymbolLoader::say(const std::string& message) const {
    if (sink) sink(message);
}

SymbolProvider& SymbolLoader::provider() const {
    return *debug.getSymbolProvider();
}

void SymbolLoader::setSearchPath(const std::string& path) {
    directories = split(path);
    applySearchPath();
}

// After the caller's directories: a symbol file kept beside a dump or a trace
// matches the image in it, and must come before a same-named file from another
// build in a shared cache.
void SymbolLoader::useSymbolsBeside(const std::string& file) {
    std::string directory = directoryOf(file);
    if (directory.empty()) return;
    if (std::find(directories.begin(), directories.end(), directory)
            != directories.end())
        return;

    directories.push_back(directory);
    applySearchPath();
}

// Given to the debugger's symbol options too, so that a symbol backend created
// when a dump or a trace is opened starts with it.
void SymbolLoader::applySearchPath() {
    joinedPath = joined(directories);
    options.searchPath = joinedPath;
    debug.setSymbolOptions(options);

    provider().setSearchPath(joinedPath);
    // The engine's whole path, with the cache and server it added. Empty until
    // a target is open.
    std::string effective = provider().searchPath();
    if (!effective.empty()) say("searching: " + effective);
}

// Exact first: a load that accepts a nearby build also succeeds with the exact
// file, so tried first it would report every module as mismatched.
SymbolState SymbolLoader::load(const std::string& module) {
    if (module.empty()) return SymbolState::Missing;
    if (provider().moduleNamed(module).hasSymbolFile()) return SymbolState::Matched;

    if (provider().loadModuleSymbols(module, SymbolMatch::Exact))
        return SymbolState::Matched;
    if (provider().loadModuleSymbols(module, SymbolMatch::Nearest))
        return SymbolState::Mismatched;
    return SymbolState::Missing;
}

bool SymbolLoader::report(const std::string& module, SymbolState state,
                          const std::string& note) const {
    switch (state) {
    case SymbolState::Matched:
        say("symbols: " + module + " <- " + provider().moduleNamed(module).symbolFile);
        return true;
    case SymbolState::Mismatched:
        say("WARNING: no symbol file for this build of " + module + " was found;"
            " loaded one from another build instead: "
            + provider().moduleNamed(module).symbolFile);
        say("WARNING: its addresses may not match, so treat anything that reads"
            " oddly as suspect.");
        return true;
    case SymbolState::Missing:
        reportMissing(module, note);
        return false;
    }
    return false;
}

void SymbolLoader::reportMissing(const std::string& module,
                                 const std::string& note) const {
    say("no symbols for " + module + ": no symbol file, not even one from"
        " another build, was found under "
        + (joinedPath.empty() ? std::string("the search path") : joinedPath) + ".");
    if (!note.empty()) say(note);
    say("put " + module + "'s symbol file beside the target, or add its"
        " directory to the search path.");
}

bool SymbolLoader::loadAndReport(const std::string& module,
                                 const std::string& note) {
    return report(module, load(module), note);
}

void SymbolLoader::reportModules() const {
    if (!sink) return;
    for (const auto& module : provider().getModules()) {
        if (!verbose && isSystemModule(module.path)) continue;
        say(verbose ? atLength(module) : briefly(module));
    }
}

} // namespace smalldbg
