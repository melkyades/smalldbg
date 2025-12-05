// Symbol backend interface - allows plugging in different symbol resolution systems
#pragma once

#include "Types.h"
#include <string>
#include <optional>

namespace smalldbg {

// Forward declarations
struct Symbol;
struct SourceLocation;
struct SymbolOptions;

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
    
    // Source/line information
    virtual std::optional<SourceLocation> getSourceLocation(Address addr) = 0;
    
    // Status
    virtual bool isInitialized() const = 0;
};

} // namespace smalldbg
