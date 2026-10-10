#pragma once

#include <VMModule.h>

#include <functional>
#include <iosfwd>
#include <memory>
#include <string>

namespace smalldbg { class Arch; class Debugger; }

namespace vmreport {

/** Options holds what a report's command line asked for. Every dialect's
 *  report takes the same options. **/
struct Options {
    std::string target;   // the dump or trace to read
    std::string output;   // where the report goes
    std::string symbols;  // directories to search for symbol files
    std::string sources;  // where the dialect's sources are
};

/** Reads the command line into `options`. Unless a symbol path is given, it
 *  takes the one in the setup file beside the target, if there is one.
 *  Returns false, after printing the usage, when no target is named. **/
bool parseCommandLine(int argc, char* argv[], Options& options);

/** Returns a debugger for the target `options` names, with `arch` as the
 *  target's architecture, logging the engine's messages to stderr. **/
std::unique_ptr<smalldbg::Debugger> makeDebugger(const Options& options,
                                                 const smalldbg::Arch* arch);

/** Opens the target and loads the symbols of the VM's module. Returns false,
 *  after saying why, when the target cannot be opened or the VM cannot be
 *  read without a symbol file that was not found. **/
bool openTarget(smalldbg::Debugger& debugger, const Options& options,
                const vmdbg::VMModule& vm);

/** Writes what the report knows about a stopped target: why it stopped, its
 *  modules, the VM's section, which `vmSection` writes, and the native
 *  threads with their stacks. **/
void writeReport(smalldbg::Debugger& debugger, const std::string& target,
                 const std::function<void(std::ostream&)>& vmSection,
                 std::ostream& out);

/** Writes the report to the file `options` names and says so. Returns the
 *  exit code for main: 0, or 1 when the file cannot be written. **/
int writeReportFile(smalldbg::Debugger& debugger, const Options& options,
                    const std::function<void(std::ostream&)>& vmSection);

/** Writes a section heading, underlined. **/
void heading(std::ostream& out, const std::string& title);
/** Returns `value` in hex after "0x", padded to `width` digits. **/
std::string hex(uint64_t value, int width = 16);

} // namespace vmreport
