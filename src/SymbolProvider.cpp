#include "smalldbg/SymbolProvider.h"
#include "smalldbg/StackTrace.h"
#include "backends/Backend.h"

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

void SymbolProvider::shutdown() {
    // Shutdown all backends
    for (auto& backend : backends) {
        backend->shutdown();
    }
}

std::optional<Symbol> SymbolProvider::getSymbolByName(const std::string& name) {
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

std::vector<Symbol> SymbolProvider::findSymbols(const std::string& pattern) {
    std::vector<Symbol> results;
    for (auto& backend : backends) {
        backend->enumerateSymbols(pattern, [&](const Symbol& sym) {
            results.push_back(sym);
            return true;
        });
    }
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

