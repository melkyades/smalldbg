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
    // For now, not implemented
    (void)pattern;
    return {};
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

} // namespace smalldbg

