// Symbol provider abstraction - manages multiple symbol backends
#pragma once

#include "Types.h"
#include "SymbolBackend.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace smalldbg {

class Backend;

enum class SymbolType {
    Function,
    Variable,
    Parameter,
    Type,
    Unknown
};

struct Symbol {
    std::string name;
    Address address{0};
    uint64_t size{0};
    SymbolType type{SymbolType::Unknown};
    std::string moduleName;
};

struct SourceLocation {
    std::string filename;
    uint32_t line{0};
    uint32_t column{0};
    Address address{0};
};

// Options for symbol loading
struct SymbolOptions {
    std::string cacheDirectory = "C:\\Symbols";  // Where to cache downloaded symbols
    std::string searchPath;                       // Additional search paths (semicolon-separated)
    bool useSymbolServer = true;                  // Enable Microsoft symbol server
    std::string symbolServerUrl = "https://msdl.microsoft.com/download/symbols";
    bool deferredLoading = true;                  // Load symbols on-demand (recommended)
    bool loadLineInfo = true;                     // Load source line information
    bool undecoratenames = true;                  // Undecorate C++ names
    bool exactSymbols = false;                    // Require exact symbol matches (slower but more accurate)
};

// Concrete symbol provider that manages multiple backends
class SymbolProvider {
public:
    explicit SymbolProvider(Backend* backend);
    ~SymbolProvider();

    // Set options and pass to all backends
    void setOptions(const SymbolOptions& options);
    const SymbolOptions& getOptions() const { return symbolOptions; }
    
    void shutdown();
    
    // Add a symbol backend (takes ownership)
    void addBackend(std::unique_ptr<SymbolBackend> backend);
    
    // Symbol lookup - queries all backends in priority order
    std::optional<Symbol> getSymbolByName(const std::string& name);
    std::optional<Symbol> getSymbolByAddress(Address addr);
    std::vector<Symbol> findSymbols(const std::string& pattern);
    
    // Source/line information
    std::optional<SourceLocation> getSourceLocation(Address addr);
    std::optional<Address> getAddressFromLine(const std::string& filename, uint32_t line);
    
    // Local variables - populates frame->localVariables directly
    void getLocalVariables(StackFrame* frame);

private:
    Backend* backend;
    std::vector<std::unique_ptr<SymbolBackend>> backends;
    SymbolOptions symbolOptions;
};

} // namespace smalldbg
