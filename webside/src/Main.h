#pragma once

#include "Workspace.h"

#include <exception>
#include <iostream>
#include <memory>
#include <string>

namespace webside {

/** A DialectInfo describes a dialect's server: its name and the kinds of
 *  target it opens. The kinds are declared, so that a target the dialect
 *  cannot open is refused with a message before anything is opened. **/
struct DialectInfo {
    std::string name;          // "bee": the log prefix and the name in errors
    std::string targetSyntax;  // the target part of the usage line
    std::string extraUsage;    // more option lines; may be empty
    bool opensLaunch{true};
    bool opensAttach{true};
    bool opensDump{true};
    bool opensTrace{true};
};

/** An Invocation holds what the command line asked for. **/
struct Invocation {
    TargetSpec spec;
    int port{7000};
    std::string configPath;
    std::string symbolPath;
    int pauseMs{-1};
    bool verbose{false};
    bool ok{false};            // false when the line was wrong
};

/** Reads the command line. On anything it does not understand it prints the
 *  usage and returns an Invocation whose `ok` is false. **/
Invocation parseCommandLine(int argc, char** argv, const DialectInfo& dialect);

/** Sets up the workspace from the invocation and opens the target. Returns
 *  false, after saying why, when the target cannot be opened. **/
bool openTarget(Workspace& workspace, const Invocation& invocation,
                const DialectInfo& dialect);

/** Runs a dialect's server: reads the command line, opens the target and
 *  serves it until the server stops. A dialect's main() calls only this, with
 *  its server type, a factory for its sessions and its DialectInfo. Returns
 *  the process exit code. **/
template <typename ServerT>
int runWebside(int argc, char** argv, Workspace::SessionFactory session,
               const DialectInfo& dialect) {
    Invocation invocation = parseCommandLine(argc, argv, dialect);
    if (!invocation.ok) return 1;

    try {
        Workspace workspace(std::move(session));
        if (!openTarget(workspace, invocation, dialect)) return 1;

        ServerT server(workspace, invocation.port);
        server.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << dialect.name << ": " << e.what() << std::endl;
        return 1;
    }
}

} // namespace webside
