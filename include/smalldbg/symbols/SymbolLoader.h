#pragma once

#include "SymbolProvider.h"

#include <functional>
#include <string>
#include <vector>

namespace smalldbg {

class Debugger;

/** What came of loading a module's symbols: a symbol file built with it, one
 *  from another build of the same module, or none. **/
enum class SymbolState { Matched, Mismatched, Missing };

/** Loads modules' symbols, an exact match first and a nearby build only when
 *  there is none, and logs which symbol file each module got and what that
 *  means. Which engine does the loading is up to the symbol provider. **/
class SymbolLoader {
public:
    using LogSink = std::function<void(const std::string&)>;

    SymbolLoader(Debugger& debugger, LogSink sink = {});

    /** Directories to search for symbol files before anywhere else. Set it
     *  before opening a dump or a trace, which load their modules as they
     *  open. **/
    void setSearchPath(const std::string& path);
    const std::string& searchPath() const { return joinedPath; }

    /** Report every module, system ones included, with its symbol type, file
     *  and image. **/
    void setVerbose(bool on) { verbose = on; }

    /** Search the directory `file` is in as well. **/
    void useSymbolsBeside(const std::string& file);

    SymbolState load(const std::string& module);

    /** Logs what `state` means for `module`. Returns true when its symbols can
     *  be used: a mismatch can, with a warning, and no symbols cannot. `note`,
     *  what the caller needed them for, is logged when there are none. **/
    bool report(const std::string& module, SymbolState state,
                const std::string& note = {}) const;

    bool loadAndReport(const std::string& module, const std::string& note = {});

    /** Logs the symbol file each module got; system modules only when
     *  verbose. **/
    void reportModules() const;

private:
    void say(const std::string& message) const;
    void reportMissing(const std::string& module, const std::string& note) const;
    void applySearchPath();
    SymbolProvider& provider() const;

    Debugger& debug;
    LogSink sink;
    std::vector<std::string> directories;
    std::string joinedPath;
    SymbolOptions options;
    bool verbose{false};
};

} // namespace smalldbg
