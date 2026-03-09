// DWARF symbol backend for macOS/Linux (POSIX)
#pragma once

#include "../../include/smalldbg/SymbolBackend.h"
#include "DwarfTypes.h"
#include <vector>
#include <memory>

namespace smalldbg {

class Backend;
class ObjectFileParser;
struct ModuleInfo;
struct ModuleSymbols;

class DwarfBackend : public SymbolBackend {
public:
    explicit DwarfBackend(Backend* be);
    ~DwarfBackend() override;

    // Options
    void setOptions(const SymbolOptions& options) override { (void)options; }

    // SymbolBackend interface
    Status initialize(void* processHandle, const SymbolOptions& options) override;
    void shutdown() override;
    bool isInitialized() const override { return initialized; }
    std::optional<Symbol> getSymbolByName(const std::string& name) override;
    std::optional<Symbol> getSymbolByAddress(Address addr) override;
    void enumerateSymbols(const std::string& pattern, SymbolCallback callback) override;
    void enumerateModules(ModuleCallback callback) override;
    std::optional<SourceLocation> getSourceLocation(Address addr) override;
    void getLocalVariables(StackFrame* frame) override;

    // Type information (from DWARF debug info in .o files)
    const NativeTypeInfo* getTypeByName(const std::string& name) override;
    std::optional<std::string> getVariableTypeName(const std::string& name) override;

private:
    Backend* backend;
    void* processHandle{nullptr};
    bool initialized{false};
    bool modulesLoaded{false};
    std::string symbolSearchPath;
    std::vector<std::unique_ptr<ModuleSymbols>> modules;

    // Lazily enumerate loaded modules and parse their symbol tables
    void loadModules();

    // Load one module through the parser
    void loadOneModule(ObjectFileParser& parser, const ModuleInfo& info);

    // Lazily load DWARF type info from .o files
    void loadTypeInfo();
    DwarfTypeDatabase typeDb;
};

} // namespace smalldbg
