#pragma once

#include "Target.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace vmdbg {

/** A Setup is a developer's debugging setup for one target, as kept in a file
 *  beside it: the target, where its symbols are, the modules whose symbols
 *  were loaded by hand, breakpoints, and names given to addresses. Once it is
 *  loaded from a file, every change is written back there. **/
class Setup {
public:
    using Log = std::function<void(const std::string&)>;

    virtual ~Setup() = default;

    const TargetSpec& target() const { return spec; }
    void setTarget(const TargetSpec& target) { spec = target; }

    /** Sets the directories to search for symbols, separated by ';'. **/
    void setSymbolSearchPath(const std::string& path);
    const std::string& symbolSearchPath() const { return symbolPath; }
    void addSymbolSearchPath(const std::string& path);
    const std::vector<std::string>& symbolSearchPaths() const {
        return symbolDirs;
    }

    /** Remembers a module whose symbols were loaded by hand. **/
    void rememberSymbolModule(const std::string& module);
    const std::vector<std::string>& symbolModules() const { return symModules; }

    /** Sets a breakpoint. Returns true; a subclass that also sets it in a
     *  target returns whether that worked. **/
    virtual bool setBreakpoint(uint64_t address, const std::string& name = {});
    /** Clears a breakpoint. Returns false when there was none. **/
    virtual bool clearBreakpoint(uint64_t address);
    const std::map<uint64_t, std::string>& breakpoints() const {
        return breaks;
    }

    /** Names an address. A label takes precedence over a symbol. **/
    void setLabel(uint64_t address, const std::string& name);
    void clearLabel(uint64_t address);
    const std::map<uint64_t, std::string>& labels() const { return names; }
    /** Returns the label at `address`, or an empty name. **/
    std::string labelAt(uint64_t address) const;

    /** Reads the setup from `path` and saves it there from then on. Returns
     *  false when the file is missing or unreadable, which leaves the setup
     *  as it was: the file is written the first time the setup changes. **/
    bool load(const std::string& path);

    /** Writes the setup to the file it was loaded from. Returns false when
     *  there is no such file or it cannot be written. **/
    bool save() const;

    void setConfigPath(const std::string& path) { configFile = path; }
    const std::string& configPath() const { return configFile; }

    /** Returns the setup as JSON, as save() writes it. **/
    std::string toJson() const;

    void setLogCallback(Log callback) { logger = std::move(callback); }
    void log(const std::string& message) const;

protected:
    void saveIfConfigured() const;
    const Log& logCallback() const { return logger; }

private:
    TargetSpec spec;
    std::string symbolPath;
    std::vector<std::string> symModules;
    std::vector<std::string> symbolDirs;
    std::string configFile;
    Log logger;
    std::map<uint64_t, std::string> breaks;
    std::map<uint64_t, std::string> names;
};

} // namespace vmdbg
