#include "smalldbg/symbols/SymbolProvider.h"
#include "smalldbg/StackTrace.h"
#include "backends/Backend.h"
#include "ModuleKey.h"

#include <algorithm>

namespace smalldbg {

SymbolProvider::SymbolProvider(Backend* be) 
    : backend(be) {
}

SymbolProvider::~SymbolProvider() {
    shutdown();
}

void SymbolProvider::addBackend(std::unique_ptr<SymbolBackend> backend) {
    backends.push_back(std::move(backend));
}

void SymbolProvider::setOptions(const SymbolOptions& options) {
    symbolOptions = options;
    // Pass options to all backends
    for (auto& backend : backends) {
        backend->setOptions(symbolOptions);
    }
}

void SymbolProvider::setSearchPath(const std::string& path) {
    symbolOptions.searchPath = path;
    for (auto& backend : backends)
        backend->setSearchPath(path);
}

std::string SymbolProvider::searchPath() const {
    for (const auto& backend : backends) {
        std::string path = backend->searchPath();
        if (!path.empty()) return path;
    }
    return symbolOptions.searchPath;
}

bool SymbolProvider::loadModuleSymbols(const std::string& module,
                                       SymbolMatch match) {
    for (auto& backend : backends)
        if (backend->loadModuleSymbols(module, match)) return true;
    return false;
}

ModuleInfo SymbolProvider::moduleNamed(const std::string& module) {
    std::string wanted = moduleKey(module);
    for (const auto& known : getModules())
        if (moduleKey(known.shortName) == wanted || moduleKey(known.path) == wanted)
            return known;
    return {};
}

void SymbolProvider::preferModule(const std::string& module) {
    if (std::find(preferredModules.begin(), preferredModules.end(), module)
        == preferredModules.end())
        preferredModules.push_back(module);
}

void SymbolProvider::shutdown() {
    // Shutdown all backends
    for (auto& backend : backends) {
        backend->shutdown();
    }
}

std::optional<Symbol> SymbolProvider::getSymbolByName(const std::string& name) {
    // The database is in memory; an engine may search every module.
    for (const auto& info : symbolDatabase.find(name))
        if (!(info.source == nativeSymbols)) return symbolFor(info);

    if (name.find('!') == std::string::npos)
        for (const auto& module : preferredModules)
            for (auto& backend : backends)
                if (auto result = backend->getSymbolByName(module + "!" + name))
                    return result;

    // Query backends in priority order
    for (auto& backend : backends) {
        auto result = backend->getSymbolByName(name);
        if (result) {
            return result;
        }
    }
    return std::nullopt;
}

std::optional<Symbol> SymbolProvider::getSymbolByAddress(Address addr) {
    // Query backends in priority order
    for (auto& backend : backends) {
        auto result = backend->getSymbolByAddress(addr);
        if (result) {
            return result;
        }
    }
    return std::nullopt;
}

// A backend that reads its symbols from a file has their sizes already.
std::optional<Symbol> SymbolBackend::getSymbolWithExtent(Address addr) {
    return getSymbolByAddress(addr);
}

std::optional<Symbol> SymbolProvider::getSymbolWithExtent(Address addr) {
    for (auto& backend : backends) {
        auto result = backend->getSymbolWithExtent(addr);
        if (result) return result;
    }
    return std::nullopt;
}

std::vector<Symbol> SymbolProvider::findSymbols(const std::string& pattern) {
    std::vector<Symbol> results;
    for (auto& backend : backends) {
        backend->enumerateSymbols(pattern, [&](const Symbol& sym) {
            results.push_back(sym);
            return true;
        });
    }
    // Native symbols in the database are copies of what the backends answered.
    for (const auto& info : symbolDatabase.findMatching(pattern))
        if (!(info.source == nativeSymbols)) results.push_back(symbolFor(info));
    return results;
}

std::optional<SourceLocation> SymbolProvider::getSourceLocation(Address addr) {
    // Query backends in priority order
    for (auto& backend : backends) {
        auto result = backend->getSourceLocation(addr);
        if (result) {
            return result;
        }
    }
    return std::nullopt;
}

std::optional<Address> SymbolProvider::getAddressFromLine(const std::string& filename, uint32_t line) {
    // Not implemented yet
    (void)filename;
    (void)line;
    return std::nullopt;
}

void SymbolProvider::getLocalVariables(StackFrame* frame) {
    // Try backends in priority order, stop at first that populates variables
    for (auto& backend : backends) {
        size_t beforeCount = frame->localVariables.size();
        backend->getLocalVariables(frame);
        if (frame->localVariables.size() > beforeCount) {
            return;  // Backend populated variables, we're done
        }
    }
}

std::vector<ModuleInfo> SymbolProvider::getModules() {
    std::vector<ModuleInfo> results;
    for (auto& backend : backends) {
        backend->enumerateModules([&](const ModuleInfo& mod) {
            results.push_back(mod);
            return true;
        });
    }
    return results;
}

const NativeTypeInfo* SymbolProvider::getTypeByName(const std::string& name) {
    for (auto& backend : backends) {
        auto* result = backend->getTypeByName(name);
        if (result) return result;
    }
    return nullptr;
}

std::optional<std::string> SymbolProvider::getVariableTypeName(const std::string& name) {
    for (auto& backend : backends) {
        auto result = backend->getVariableTypeName(name);
        if (result) return result;
    }
    return std::nullopt;
}

} // namespace smalldbg


namespace smalldbg {

// Modules are registered once, so attributing an address to one costs no
// engine call; in-image modules are added through addModule as well.
void SymbolProvider::rememberNativeSymbol(Address address) {
    if (!nativeSymbols.valid())
        nativeSymbols = symbolDatabase.addSource("native symbols", Volatility::Stable);

    if (!modulesRegistered) {
        modulesRegistered = true;
        for (const auto& module : getModules())
            symbolDatabase.addModule(module.shortName, ModuleKind::Native,
                                     module.loadAddress, module.endAddress);
    }

    // Outside every module there is nothing for the symbol engine to say, and
    // asking is the slowest way to learn that.
    if (!symbolDatabase.moduleAt(address).valid()) return;

    // With its size, so that the rest of the function is found here too.
    auto symbol = getSymbolWithExtent(address);
    if (!symbol || symbol->name.empty()) return;
    symbolDatabase.add(symbol->address, symbol->size, symbol->name,
                       SymbolKind::Code, SymbolLayer::Symbol, nativeSymbols);
}

Symbol SymbolProvider::symbolFor(const SymbolicInfo& info) const {
    Symbol symbol;
    symbol.name = info.name;
    symbol.address = info.start;
    symbol.size = info.size;
    symbol.type = info.kind == SymbolKind::Code ? SymbolType::Function
                : info.kind == SymbolKind::Data ? SymbolType::Variable
                                                : SymbolType::Unknown;
    // An entry outside every module goes by the source that added it.
    symbol.moduleName = info.module.valid() ? symbolDatabase.moduleName(info.module)
                                            : symbolDatabase.sourceName(info.source);
    return symbol;
}

std::optional<SymbolicInfo> SymbolProvider::symbolicInfoFor(Address address) {
    if (auto known = symbolDatabase.symbolicInfoFor(address)) return known;
    rememberNativeSymbol(address);
    return symbolDatabase.symbolicInfoFor(address);
}

} // namespace smalldbg
