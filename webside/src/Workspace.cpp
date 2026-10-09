#include "Workspace.h"
#include "WebsideSession.h"

namespace webside {

Workspace::Workspace(SessionFactory factory)
    : makeSession(std::move(factory)) {}

Workspace::~Workspace() = default;

bool Workspace::setBreakpoint(uint64_t address, const std::string& name) {
    Setup::setBreakpoint(address, name);
    return current ? current->setBreakpoint(address, name) : true;
}

bool Workspace::clearBreakpoint(uint64_t address) {
    bool known = Setup::clearBreakpoint(address);
    return current ? current->clearBreakpoint(address) : known;
}

bool Workspace::open(const TargetSpec& target) {
    close();
    setTarget(target);

    auto session = makeSession(target);
    // A dump or a trace loads its modules while opening, so the search path
    // must be set first.
    session->setOpeningLog(logCallback());
    session->setSymbolSearchPath(symbolSearchPath());
    session->setVerboseSymbolLogging(verbose);
    session->setStartupPause(startupPause);
    if (!session->open(target)) return false;

    current = std::move(session);
    loadRememberedSymbols();
    applyBreakpoints();
    saveIfConfigured();
    return true;
}

void Workspace::close() {
    current.reset();
}

void Workspace::loadRememberedSymbols() {
    for (const auto& module : symbolModules())
        current->loadModuleSymbols(module);
}

void Workspace::applyBreakpoints() {
    for (const auto& [address, name] : breakpoints())
        current->setBreakpoint(address, name);
}

} // namespace webside
