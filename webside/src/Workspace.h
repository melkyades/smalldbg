#pragma once

#include "Setup.h"
#include "Target.h"

#include <memory>
#include <string>

namespace webside {

using vmdbg::TargetKind;
using vmdbg::TargetSpec;
using vmdbg::targetKindFor;

class WebsideSession;

/** A Workspace is a developer's debugging setup together with the one
 *  session it has open. The setup outlives the session: opening again builds
 *  a new session from the same setup, and breakpoints set at any time reach
 *  every session. A dialect does not subclass the workspace: it supplies a
 *  factory that builds its kind of session. **/
class Workspace : public vmdbg::Setup {
public:
    /** Builds a session for the target about to be opened. The workspace
     *  calls it on every open(). **/
    using SessionFactory =
        std::function<std::unique_ptr<WebsideSession>(const TargetSpec&)>;

    explicit Workspace(SessionFactory factory);
    ~Workspace() override;

    /** Sets how many milliseconds a launched target runs before it is
     *  suspended, so that the VM has time to build its heap; -1 lets it run.
     **/
    void setStartupPause(int milliseconds) { startupPause = milliseconds; }
    int startupPauseMs() const { return startupPause; }
    void setVerboseLogging(bool on) { verbose = on; }
    bool verboseLogging() const { return verbose; }

    /** Sets a breakpoint in the setup and in the open session, if any.
     *  Returns false when the session could not set it. **/
    bool setBreakpoint(uint64_t address, const std::string& name = {}) override;
    /** Clears a breakpoint in the setup and in the open session, if any.
     *  Returns false when there was none to clear. **/
    bool clearBreakpoint(uint64_t address) override;

    /** Closes the open session, if any, and opens `target` in a new one.
     *  Returns false when the target cannot be opened, which leaves no
     *  session open. **/
    bool open(const TargetSpec& target);
    /** Opens the last target again, in a new session. **/
    bool reopen() { return open(target()); }
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

    SessionFactory makeSession;
    int startupPause{-1};
    bool verbose{false};
    std::unique_ptr<WebsideSession> current;
};

} // namespace webside
