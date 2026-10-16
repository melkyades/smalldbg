#pragma once

#include "MemoryTypeMap.h"
#include "Target.h"
#include "VMInspector.h"
#include "VMModule.h"

#include <smalldbg/symbols/SymbolLoader.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace smalldbg {
    class Debugger;
    class Thread;
}

namespace vmdbg {

/** A VMSession models a connection to one virtual machine, running in a live
 *  process, a dump or a trace. A session opens the target, runs and stops it,
 *  and answers questions about the VM's state. Each VM has its own subclass,
 *  which reads what it needs when the target opens and drops what it cached
 *  when the target runs. **/
class VMSession {
public:
    virtual ~VMSession() = default;

    // ---- opening a target --------------------------------------------------

    /** Opens the target, loads the VM's symbols, and lets the subclass read
     *  the VM. Returns false when the target cannot be opened or used. **/
    bool open(const TargetSpec& target);

    /** Sets the directories to search for symbol files first. Call it before
     *  open(): a dump or a trace loads its modules while opening. **/
    void setSymbolSearchPath(const std::string& path);

    /** Makes the symbol report cover every module, system ones included. **/
    void setVerboseSymbolLogging(bool on);

    /** Sets how many milliseconds a launched target runs before it is
     *  suspended, so that the VM has time to build its heap; -1 lets it run.
     **/
    void setStartupPause(int milliseconds) { startupPause = milliseconds; }

    /** Sets where messages about opening a target go, such as which symbol
     *  file each module got. **/
    void setOpeningLog(smalldbg::SymbolLoader::LogSink sink);

    /** Returns true while the debugger holds the target. **/
    virtual bool isActive() const = 0;
    virtual std::optional<int> getPid() const = 0;

    // ---- run control -------------------------------------------------------

    bool resume();
    bool suspend();
    bool step();
    bool stepOver();
    bool stepOut();
    bool stepBack();
    bool reverseStepOver();
    bool reverseStepOut();
    /** Steps over the call in frame `frameIndex`; by default, in the current
     *  frame. **/
    virtual bool stepOver(int frameIndex);
    /** Runs the target until it reaches `address`. Returns false when it
     *  stopped elsewhere or did not get there in time. **/
    bool runToAddress(uint64_t address);
    /** Runs a replay backwards until it reaches `address`. Returns false
     *  when it stopped elsewhere, did not get there in time, or the target is
     *  not a replay. **/
    bool reverseRunToAddress(uint64_t address);
    /** Runs the target until it writes any of the `size` bytes at `address`,
     *  or a replay backwards to the last time it did. Returns false when the
     *  debugger cannot watch memory, the target stopped elsewhere, or it did
     *  not get there in time, when it is stopped where it was. **/
    bool runToWrite(uint64_t address, size_t size, bool backwards);
    /** Runs a replay backwards to a breakpoint or to its start. Returns
     *  false when the target is not a replay. **/
    bool reverseResume();
    /** Moves a replay to `position`, or `percent` of the way through its
     *  trace. Returns false when the target is not a replay. **/
    bool seekTrace(const smalldbg::TracePosition& position);
    bool seekTrace(double percent);

    // ---- the VM's screen ---------------------------------------------------
    /** Runs the target until the VM next puts a different picture in its
     *  window, when the framebuffer holds a whole frame. Returns false when the
     *  VM names no function it does that with, or the target did not get there
     *  in time. **/
    bool runToNextFrame();
    /** Runs a replay backwards to the last time the VM put a different
     *  picture in its window. Returns false when the VM names no function it
     *  does that with, the target did not get there in time, or the target is
     *  not a replay. **/
    bool reverseRunToPreviousFrame();
    /** Returns the picture the VM last put in its window. In a replay that
     *  stands between two screen updates, the framebuffer may be halfway
     *  through the next picture, so the one shown is read where it was put
     *  in the window. Returns nothing when the VM keeps no framebuffer. **/
    std::optional<Framebuffer> shownFramebuffer();

    // ---- breakpoints -------------------------------------------------------
    virtual bool setBreakpoint(uint64_t address, const std::string& name = "");
    virtual bool clearBreakpoint(uint64_t address);

    // ---- state -------------------------------------------------------------
    /** Returns why the target is stopped, as one word. **/
    virtual std::string getStopReason() const = 0;

    // ---- green threads (the VM's own, not the OS's) ------------------------
    virtual void refreshGreenThreads() = 0;
    virtual int greenThreadCount() const = 0;
    virtual std::string getGreenThreadName(int threadIndex) const = 0;
    /** Returns whether that green thread still has a stack to show; true when
     *  the VM cannot tell. **/
    virtual bool isGreenThreadLive(int /*threadIndex*/) const { return true; }
    /** Returns the index of the green thread the VM is running, or -1 when it
     *  cannot tell. **/
    virtual int activeGreenThread() const { return -1; }
    /** Returns the green thread this OS thread is running, or an empty name.
     **/
    virtual std::string greenThreadOn(uint64_t /*nativeThreadId*/) const { return {}; }
    /** Returns the OS thread running that green thread, whose stack holds its
     *  current frames; 0 when it is not running. **/
    virtual uint64_t nativeThreadOf(int /*threadIndex*/) const { return 0; }

    // ---- classes -----------------------------------------------------------
    virtual bool discoverClasses() = 0;

    // ---- the debugger and the inspector -----------------------------------
    // The debugger and the inspector live as long as the session.
    virtual smalldbg::Debugger& debugger() const = 0;
    virtual VMInspector& inspector() const = 0;

    /** Loads one module's symbols now. Returns false when no symbol file was
     *  loaded. **/
    virtual bool loadModuleSymbols(const std::string& module);

    /** Runs a command in the debugger's engine and returns what it printed.
     *  The command may have moved the target, so what was read from it is
     *  read again. **/
    std::string runEngineCommand(const std::string& command);

    // ---- thread helpers ----------------------------------------------------
    std::shared_ptr<smalldbg::Thread> resolveThread(uint64_t threadId) const;
    /** Returns the OS thread the VM runs on, or null when it cannot be
     *  found. **/
    virtual std::shared_ptr<smalldbg::Thread> vmThread() const = 0;

    /** Returns the target's pointer width. **/
    size_t pointerSize() const;

    // ---- memory types ------------------------------------------------------

    /** Returns how each stretch of target memory is shown in a listing. The
     *  defaults come from the modules' sections and the VM's regions, and are
     *  laid out again once the target has moved. **/
    MemoryTypeMap& memoryTypes() const;

    /** Makes the next memoryTypes() lay the defaults out again, for a target
     *  that moved without the debugger seeing it, such as a trace a raw
     *  engine command repositioned. **/
    void forgetMemoryTypeDefaults() { memoryTypesVersion.reset(); }

protected:
    // ---- what a subclass does when the target runs or stops ---------------

    /** The session calls this before the target runs, so that the subclass
     *  can drop what it read from it. **/
    virtual void beforeTargetRuns() {}

    /** The session calls this once the target has stopped and can be read
     *  again. **/
    virtual void afterTargetStops() {}

    /** The session calls this when the target may have moved without running,
     *  such as after an engine command, so that the subclass can drop what it
     *  read from it. **/
    virtual void targetMayHaveMoved() {}

    // ---- opening hooks -----------------------------------------------------

    /** Returns the module the VM's own symbols are in, and whether it needs a
     *  symbol file. **/
    virtual VMModule vmModule() const { return {}; }

    /** Returns the functions, as module!name, that the VM calls to put its
     *  screen in a window. By default there are none. **/
    virtual std::vector<std::string> screenUpdateFunctions() const { return {}; }

    /** Loads the VM module's symbols and reports them. Returns false when there
     *  are none it can use, so the target is refused. **/
    virtual bool bringInVMSymbols(const TargetSpec& target);

    /** The session calls this once the target is open and its symbols are
     *  loaded, for the subclass to read what it needs. Returns false when the
     *  subclass cannot use the target. **/
    virtual bool onTargetOpened(const TargetSpec& target) = 0;

    /** Returns true for a target that is read rather than run, such as an
     *  image file: nothing is opened in the debugger, and onTargetOpened does
     *  all the opening. **/
    virtual bool readsWithoutEngine(const TargetSpec& /*target*/) const {
        return false;
    }

    /** Returns the symbol loader, which knows where symbol files are searched
     *  for and what each module got. **/
    smalldbg::SymbolLoader& symbols() const;

    /** Logs a message about opening the target: to the opening log, or to
     *  stderr tagged with dialectTag() while none is set. **/
    void logOpening(const std::string& message) const;

    /** Returns the short word that log lines are tagged with. **/
    virtual const char* dialectTag() const { return "vm"; }

    /** The session calls this before walking a stack, so that the subclass can
     *  read what it needs to name frames: some reads fail while an unwind is in
     *  progress. **/
    virtual void prepareFrames() const {}

    /** The session calls this after laying out the memory-type defaults from
     *  the modules and the regions, for the subclass to add what only it
     *  knows, such as where each object's header is. **/
    virtual void addMemoryTypeDefaults(MemoryTypeMap& /*types*/) const {}

    /** Returns the first thread whose stack pointer `onStack` accepts, or null
     *  when none does or the target is running. **/
    std::shared_ptr<smalldbg::Thread> threadWithStackPointer(
        const std::function<bool(uint64_t)>& onStack) const;

    /** Returns the thread whose native stack holds a frame of the named
     *  function, or null when none does or the target is running. It unwinds
     *  every thread, so the answer is kept until the target moves. **/
    std::shared_ptr<smalldbg::Thread> threadRunning(const std::string& function) const;

    const std::string& symbolSearchPath() const { return symbols().searchPath(); }
    int startupPauseMs() const { return startupPause; }

private:
    mutable std::unique_ptr<smalldbg::SymbolLoader> loader;
    smalldbg::SymbolLoader::LogSink openingLog;
    int startupPause{-1};
    mutable std::shared_ptr<smalldbg::Thread> runningThread;
    mutable uint64_t runningThreadVersion{0};  // debugger stateVersion it is from

    void layOutMemoryTypes() const;
    mutable MemoryTypeMap memTypes;
    mutable std::optional<uint64_t> memoryTypesVersion;  // stateVersion of the defaults
    mutable std::vector<MemTypeRange> sectionTypes;     // the modules' sections

    /** Runs forwards or backwards to the next call of a screen update
     *  function that shows a different picture. **/
    bool runToFrame(bool backwards);
    /** Returns where the screen update functions are; none when the VM names
     *  none or their symbols are missing. **/
    std::vector<uint64_t> screenUpdateAddresses() const;
    /** Runs forwards or backwards to the next call of any of `addresses`.
     *  Returns false when the target did not get there in time, or stopped
     *  somewhere else. **/
    bool runToScreenUpdate(bool backwards, const std::vector<uint64_t>& addresses);
    /** Sets a breakpoint at each of `addresses` that has none, and returns
     *  those it set. **/
    std::vector<uint64_t> addBreakpointsAt(const std::vector<uint64_t>& addresses);
    /** Returns true when the current thread stands at one of `addresses`. **/
    bool atScreenUpdate(const std::vector<uint64_t>& addresses) const;
};

} // namespace vmdbg
