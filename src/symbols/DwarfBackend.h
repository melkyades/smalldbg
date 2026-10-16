// DWARF symbol backend for macOS/Linux (POSIX)
#pragma once

#include "../../include/smalldbg/symbols/SymbolSource.h"
#include "DwarfTypes.h"
#include "ObjectFileParser.h"
#include <memory>
#include <unordered_map>
#include <vector>

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
    bool loadModuleSymbols(const std::string& module, SymbolMatch match) override;
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
    uint64_t modulesVersion{0};  // target version the modules are from
    std::string symbolSearchPath;
    std::vector<std::unique_ptr<ModuleSymbols>> modules;

    // Enumerate the loaded modules once per target version, parsing the
    // symbol tables of those not seen before.
    void loadModules();
    std::unique_ptr<ModuleSymbols> takeOrLoadModule(const ModuleInfo& info);
    std::unique_ptr<ModuleSymbols> loadOneModule(const ModuleInfo& info);
    // The module, with its symbols read the first time they are needed
    ModuleSymbols& symbolsOf(ModuleSymbols& mod);
    smalldbg_internal::MemoryReader targetMemory() const;
    std::unique_ptr<ObjectFileParser> parser;

    ModuleSymbols* moduleNamed(const std::string& module);
    bool enumerateModuleSymbols(const ModuleSymbols& mod, const std::string& pattern,
                                const SymbolCallback& callback);
    std::optional<Symbol> symbolNamed(const ModuleSymbols& mod,
                                      const std::string& name);

    // DWARF type info, read from each module's .o files when first needed
    std::unordered_map<std::string, std::unique_ptr<DwarfTypeDatabase>> typeDatabases;
    const DwarfTypeDatabase* typesOf(const ModuleSymbols& mod);
    const DwarfTypeDatabase* mainTypes();
    const DwarfTypeDatabase* typesFor(std::string& name, std::string& module);

    // Source location cache (address → resolved location or nullopt)
    std::unordered_map<Address, std::optional<SourceLocation>> sourceLocationCache;
};

} // namespace smalldbg
