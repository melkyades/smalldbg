// Internal types shared between DwarfBackend and ObjectFileParser implementations.
#pragma once

#include "../../include/smalldbg/Types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstdlib>
#include <cxxabi.h>

namespace smalldbg {

// A single resolved symbol (address already slid to runtime address)
struct ResolvedSymbol {
    Address address;
    std::string name;     // demangled (e.g. "Egg::KnownObjects::nil")
    std::string rawName;  // mangled without leading _ (e.g. "_ZN3Egg12KnownObjects3nilE")
    uint64_t size;        // estimated from the gap to the next symbol
};

// Symbols for one loaded module
struct ModuleSymbols {
    std::string path;
    std::string shortName; // filename component only
    Address loadAddress;
    Address textEnd;       // upper bound of __TEXT / .text segment (slid)
    std::vector<ResolvedSymbol> symbols; // sorted by address

    // Maps for O(1) name lookup: demangled name -> index, raw name -> index
    std::unordered_map<std::string, size_t> nameIndex;
    std::unordered_map<std::string, size_t> rawNameIndex;

    // Build name indexes after symbols are loaded (call once after parsing)
    void buildNameIndexes() {
        for (size_t i = 0; i < symbols.size(); i++) {
            nameIndex.emplace(symbols[i].name, i);
            if (symbols[i].rawName != symbols[i].name)
                rawNameIndex.emplace(symbols[i].rawName, i);
        }
    }

    // Binary search: find the symbol whose address is <= addr
    const ResolvedSymbol* findSymbol(Address addr) const {
        if (symbols.empty()) return nullptr;
        auto it = std::upper_bound(symbols.begin(), symbols.end(), addr,
            [](Address a, const ResolvedSymbol& s) { return a < s.address; });
        if (it == symbols.begin()) return nullptr;
        --it;
        return &(*it);
    }
};

// Demangle a C++ symbol name. Returns the original if demangling fails.
inline std::string demangle(const char* name) {
    int status = 0;
    char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::string result(demangled);
        free(demangled);
        return result;
    }
    return name;
}

// Extract the filename component from a path
inline std::string filenameOf(const std::string& path) {
    auto pos = path.rfind('/');
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

} // namespace smalldbg
