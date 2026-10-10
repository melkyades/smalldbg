// DbgEng symbol backend — uses IDebugSymbols3 for symbol resolution.
//
// This backend is used when debugging via the DbgEng engine (e.g. TTD traces,
// or any DbgEngBackend session).  It delegates all symbol lookups to DbgEng's
// built-in symbol engine, which supports PDB, DWARF, and Microsoft Symbol
// Server out of the box.
#pragma once

#include "../../include/smalldbg/symbols/SymbolSource.h"
#include "../../include/smalldbg/symbols/SymbolProvider.h"

#include <windows.h>
#include <dbgeng.h>
#include <set>
#include <map>
#include <string>
#include <vector>

namespace smalldbg {

class DbgEngSymbolBackend : public SymbolBackend {
public:
    /** The caller keeps ownership of `symbols` and `control`, which must
     *  outlive this backend. **/
    DbgEngSymbolBackend(IDebugSymbols3* symbols, IDebugControl4* control);
    ~DbgEngSymbolBackend() override;

    // Options
    void setOptions(const SymbolOptions& opts) override { options = opts; }

    // Initialization — for DbgEng the interfaces are already created,
    // so processHandle is ignored.
    Status initialize(void* processHandle, const SymbolOptions& opts) override;
    void shutdown() override;

    void setSearchPath(const std::string& path) override;
    std::string searchPath() const override;
    bool loadModuleSymbols(const std::string& module, SymbolMatch match) override;

    // Symbol lookup
    std::optional<Symbol> getSymbolByName(const std::string& name) override;
    std::optional<Symbol> getSymbolByAddress(Address addr) override;
    std::optional<Symbol> getSymbolWithExtent(Address addr) override;

    /** Returns the layout of the type named `name`, such as
     *  "test_target!TestRecord", or null when the pdb has none. The name must
     *  carry its module: a bare one gives the engine nowhere to look. The
     *  result stays valid as long as the backend. **/
    const NativeTypeInfo* getTypeByName(const std::string& name) override;

    /** Returns the module-qualified name of the type the global `name` holds,
     *  or nothing when the pdb does not say. **/
    std::optional<std::string> getVariableTypeName(const std::string& name) override;
    void enumerateSymbols(const std::string& pattern, SymbolCallback callback) override;

    // Module enumeration
    void enumerateModules(ModuleCallback callback) override;

    // Source/line information
    std::optional<SourceLocation> getSourceLocation(Address addr) override;

    // Local variables (not yet implemented for DbgEng)
    void getLocalVariables(StackFrame* frame) override;

    // Status
    bool isInitialized() const override { return initialized; }

private:
    /** Adds the variables of the engine's current scope to `frame`. **/
    void readScopeVariables(StackFrame& frame);

    std::optional<std::string> lookUpVariableTypeName(const std::string& name);

    // Each lookup searches the pdb, which takes seconds on a large one, so
    // misses are remembered as well as hits.
    std::map<std::string, std::optional<NativeTypeInfo>> typeCache;
    std::map<std::string, std::optional<std::string>> variableTypeCache;

    void applySearchPath(const std::string& callerPath);

    /** The base and image file name of the module whose image or module name
     *  is `module`. Returns false when none matches. **/
    bool findModule(const std::string& module, ULONG64& base, std::string& imageFile);

    /** Returns true when the module at `base` has a symbol file rather than
     *  its export table. A reload succeeds either way, so it cannot tell. **/
    bool hasSymbolFile(ULONG64 base);

    /** Loads the symbols of the module holding `addr`, once per module.
     *  Returns false when that was already tried or nothing holds `addr`. **/
    bool loadSymbolsAt(Address addr);
    std::set<ULONG64> symbolsLoadedAt;

    /** The names of the modules whose symbols are loaded. **/
    std::vector<std::string> modulesWithSymbols();

    /** Matches `pattern` with the engine. Returns false when `callback` asked
     *  to stop. **/
    bool matchSymbols(const std::string& pattern, const SymbolCallback& callback);

    IDebugSymbols3* symbols = nullptr;
    IDebugControl4* control = nullptr;
    SymbolOptions options;
    bool initialized = false;
};

} // namespace smalldbg
