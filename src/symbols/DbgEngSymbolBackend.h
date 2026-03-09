// DbgEng symbol backend — uses IDebugSymbols3 for symbol resolution.
//
// This backend is used when debugging via the DbgEng engine (e.g. TTD traces,
// or any DbgEngBackend session).  It delegates all symbol lookups to DbgEng's
// built-in symbol engine, which supports PDB, DWARF, and Microsoft Symbol
// Server out of the box.
#pragma once

#include "../../include/smalldbg/SymbolBackend.h"
#include "../../include/smalldbg/SymbolProvider.h"

#include <windows.h>
#include <dbgeng.h>
#include <string>

namespace smalldbg {

class DbgEngSymbolBackend : public SymbolBackend {
public:
    /// Construct with pointers to DbgEng's IDebugSymbols3 and IDebugControl4.
    /// The caller retains ownership — these must outlive this object.
    DbgEngSymbolBackend(IDebugSymbols3* symbols, IDebugControl4* control);
    ~DbgEngSymbolBackend() override;

    // Options
    void setOptions(const SymbolOptions& opts) override { options = opts; }

    // Initialization — for DbgEng the interfaces are already created,
    // so processHandle is ignored.
    Status initialize(void* processHandle, const SymbolOptions& opts) override;
    void shutdown() override;

    // Symbol lookup
    std::optional<Symbol> getSymbolByName(const std::string& name) override;
    std::optional<Symbol> getSymbolByAddress(Address addr) override;
    void enumerateSymbols(const std::string& pattern, SymbolCallback callback) override;

    // Source/line information
    std::optional<SourceLocation> getSourceLocation(Address addr) override;

    // Local variables (not yet implemented for DbgEng)
    void getLocalVariables(StackFrame* frame) override;

    // Status
    bool isInitialized() const override { return initialized; }

private:
    IDebugSymbols3* symbols = nullptr;
    IDebugControl4* control = nullptr;
    SymbolOptions options;
    bool initialized = false;
};

} // namespace smalldbg
