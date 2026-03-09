// Symbol backend interface - allows plugging in different symbol resolution systems
#pragma once

#include "Types.h"
#include <string>
#include <optional>
#include <vector>
#include <functional>

namespace smalldbg {

// Forward declarations
struct Symbol;
struct SourceLocation;
struct SymbolOptions;
struct ModuleInfo;
struct LocalVariable;
struct StackFrame;
struct NativeTypeInfo;

// Abstract interface for symbol backends (DbgHelp, DWARF, user-defined, etc.)
class SymbolBackend {
public:
    virtual ~SymbolBackend() = default;

    // Options can be set before initialization
    virtual void setOptions(const SymbolOptions& options) = 0;
    
    // Initialization - called when process is attached
    virtual Status initialize(void* processHandle, const SymbolOptions& options) = 0;
    virtual void shutdown() = 0;
    
    // Symbol lookup
    virtual std::optional<Symbol> getSymbolByName(const std::string& name) = 0;
    virtual std::optional<Symbol> getSymbolByAddress(Address addr) = 0;
    
    // Enumerate symbols matching a wildcard pattern (e.g. "*Zone*")
    // Callback returns true to continue, false to stop.
    using SymbolCallback = std::function<bool(const Symbol&)>;
    virtual void enumerateSymbols(const std::string& pattern, SymbolCallback callback) {};

    // Enumerate loaded modules.
    using ModuleCallback = std::function<bool(const ModuleInfo&)>;
    virtual void enumerateModules(ModuleCallback callback) {};
    
    // Source/line information
    virtual std::optional<SourceLocation> getSourceLocation(Address addr) = 0;
    
    // Local variables at a given address (within a function)
    // Populates frame->localVariables directly
    virtual void getLocalVariables(StackFrame* frame) = 0;
    
    // Type information (DWARF-based)
    virtual const NativeTypeInfo* getTypeByName(const std::string& /*name*/) { return nullptr; }
    virtual std::optional<std::string> getVariableTypeName(const std::string& /*name*/) { return std::nullopt; }

    // Status
    virtual bool isInitialized() const = 0;
};

} // namespace smalldbg
