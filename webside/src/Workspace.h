#pragma once

#include "Target.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace webside {

using vmdbg::TargetKind;
using vmdbg::TargetSpec;
using vmdbg::targetKindFor;

class WebsideSession;

/** A Workspace holds the developer's debugging setup and the one session it
 *  has open. The setup is what the developer configured, such as the target
 *  and the symbol paths, and what they added while working: breakpoints and
 *  address labels. A session connects to one process, trace or dump; the
 *  setup outlives it, and opening again builds a new session from the same
 *  setup. A dialect does not subclass the workspace: it supplies a factory
 *  that builds its kind of session. **/
class Workspace {
public:
    /** Builds a session for the target about to be opened. The workspace
     *  calls it on every open(). **/
    using SessionFactory =
        std::function<std::unique_ptr<WebsideSession>(const TargetSpec&)>;

    explicit Workspace(SessionFactory factory);
    ~Workspace();

    // ---- configuration -----------------------------------------------------

    const TargetSpec& target() const { return spec; }
    void setTarget(const TargetSpec& target) { spec = target; }

    /** Sets the directories to search for symbols, separated by ';'. **/
    void setSymbolSearchPath(const std::string& path);
    const std::string& symbolSearchPath() const { return symbolPath; }
    void addSymbolSearchPath(const std::string& path);
    const std::vector<std::string>& symbolSearchPaths() const {
        return symbolDirs;
    }

    /** Remembers a module whose symbols the developer loaded by hand, so that
     *  the next session loads them too. **/
    void rememberSymbolModule(const std::string& module);
    const std::vector<std::string>& symbolModules() const { return symModules; }

    /** Sets how many milliseconds a launched target runs before it is
     *  suspended, so that the VM has time to build its heap; -1 lets it run.
     **/
    void setStartupPause(int milliseconds) { startupPause = milliseconds; }
    int startupPauseMs() const { return startupPause; }
    void setVerboseLogging(bool on) { verbose = on; }
    bool verboseLogging() const { return verbose; }
    void setLogCallback(std::function<void(const std::string&)> callback);
    void log(const std::string& message) const;

    // ---- what the developer adds, kept across sessions ---------------------

    /** Sets a breakpoint in the open session, if any, and in every session
     *  opened later. **/
    bool setBreakpoint(uint64_t address, const std::string& name = {});
    bool clearBreakpoint(uint64_t address);
    const std::map<uint64_t, std::string>& breakpoints() const {
        return breaks;
    }

    /** Names an address. A label takes precedence over a symbol. **/
    void setLabel(uint64_t address, const std::string& name);
    void clearLabel(uint64_t address);
    const std::map<uint64_t, std::string>& labels() const { return names; }
    /** Returns the label at `address`, or an empty name. **/
    std::string labelAt(uint64_t address) const;

    // ---- the setup on disk -------------------------------------------------

    /** Reads the setup from `path` and saves it there from then on. Returns
     *  false when the file is missing or unreadable, which leaves the setup
     *  empty: the file is written the first time the setup changes. **/
    bool load(const std::string& path);

    /** Writes the setup to the file it was loaded from. Returns false when
     *  there is no such file or it cannot be written. **/
    bool save() const;

    void setConfigPath(const std::string& path) { configFile = path; }
    const std::string& configPath() const { return configFile; }

    /** Returns the setup as JSON, as save() writes it. **/
    std::string toJson() const;

    // ---- the session -------------------------------------------------------

    /** Closes the open session, if any, and opens `target` in a new one.
     *  Returns false when the target cannot be opened, which leaves no
     *  session open. **/
    bool open(const TargetSpec& target);
    /** Opens the last target again, in a new session. **/
    bool reopen() { return open(spec); }
    void close();

    bool isConnected() const { return current != nullptr; }
    /** Returns the open session, or null when none is open. The session
     *  stays valid until the next open() or close(). **/
    WebsideSession* session() const { return current.get(); }

    /** Returns the open session as the dialect's own type, or null when none
     *  is open or it is of another type. **/
    template <typename SessionT>
    SessionT* sessionAs() const {
        return dynamic_cast<SessionT*>(current.get());
    }

private:
    void loadRememberedSymbols();
    void applyBreakpoints();
    void saveIfConfigured() const;

    SessionFactory makeSession;
    TargetSpec spec;
    std::string symbolPath;
    std::vector<std::string> symModules;
    std::vector<std::string> symbolDirs;
    std::string configFile;
    int startupPause{-1};
    bool verbose{false};
    std::function<void(const std::string&)> logger;
    std::map<uint64_t, std::string> breaks;
    std::map<uint64_t, std::string> names;
    std::unique_ptr<WebsideSession> current;
};

} // namespace webside
