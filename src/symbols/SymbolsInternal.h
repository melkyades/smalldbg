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
    std::string name;     // demangled (e.g. "MyApp::KnownObjects::nil")
    std::string rawName;  // mangled without leading _ (e.g. "_ZN5MyApp12KnownObjects3nilE")
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

// Simplify verbose C++ standard library type names for display.
// Strips libc++ inline namespace markers (__1::, __2::, etc.) and
// replaces well-known verbose template instantiations with their aliases.
inline std::string simplifyTypeName(std::string name) {
    // Normalize "> >" to ">>" (DWARF names use spaces between closing brackets)
    size_t pos = 0;
    while ((pos = name.find("> >", pos)) != std::string::npos)
        name.erase(pos + 1, 1);

    // Strip libc++ versioned inline namespace markers (__N::)
    pos = 0;
    while ((pos = name.find("__", pos)) != std::string::npos) {
        size_t end = pos + 2;
        while (end < name.size() && name[end] >= '0' && name[end] <= '9')
            end++;
        if (end > pos + 2 && end + 1 < name.size() &&
            name[end] == ':' && name[end + 1] == ':') {
            name.erase(pos, end + 2 - pos);
        } else {
            pos = end;
        }
    }

    // Replace well-known verbose STL type instantiations with their aliases
    struct TypeAlias { const char* verbose; const char* simple; };
    static const TypeAlias aliases[] = {
        {"basic_string<char, std::char_traits<char>, std::allocator<char>>",
         "string"},
        {"basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t>>",
         "wstring"},
        {"basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t>>",
         "u16string"},
        {"basic_string<char32_t, std::char_traits<char32_t>, std::allocator<char32_t>>",
         "u32string"},
    };
    for (auto& alias : aliases) {
        pos = name.find(alias.verbose);
        if (pos != std::string::npos)
            name.replace(pos, strlen(alias.verbose), alias.simple);
    }

    // Strip [abi:...] tags (e.g. [abi:ne200100])
    pos = 0;
    while ((pos = name.find("[abi:", pos)) != std::string::npos) {
        size_t end = name.find(']', pos);
        if (end == std::string::npos) break;
        name.erase(pos, end + 1 - pos);
    }

    // Remove ", std::allocator<T>" from any template parameter list
    pos = 0;
    while ((pos = name.find(", std::allocator<", pos)) != std::string::npos) {
        size_t start = pos;
        size_t i = start + 17; // skip ", std::allocator<"
        int depth = 1;
        while (i < name.size() && depth > 0) {
            if (name[i] == '<') depth++;
            else if (name[i] == '>') depth--;
            i++;
        }
        name.erase(start, i - start);
    }

    // Remove "std::allocator<T>&, " when it appears as first function parameter
    pos = 0;
    while ((pos = name.find("std::allocator<", pos)) != std::string::npos) {
        size_t start = pos;
        size_t i = start + 15;
        int depth = 1;
        while (i < name.size() && depth > 0) {
            if (name[i] == '<') depth++;
            else if (name[i] == '>') depth--;
            i++;
        }
        // Check for trailing "&, " (allocator ref as leading param)
        if (i + 2 < name.size() && name[i] == '&' && name[i+1] == ',' && name[i+2] == ' ')
            name.erase(start, i + 3 - start);
        else
            pos = i;
    }

    // Simplify std::vector with default allocator (leftover cases)
    const char* vecPrefix = "vector<";
    pos = 0;
    while ((pos = name.find(vecPrefix, pos)) != std::string::npos) {
        size_t open = pos + strlen(vecPrefix);
        size_t allocPos = name.find(", std::allocator<", open);
        if (allocPos != std::string::npos) {
            std::string elemType = name.substr(open, allocPos - open);
            std::string expected = ", std::allocator<" + elemType + ">>";
            if (name.compare(allocPos, expected.size(), expected) == 0)
                name.replace(allocPos, expected.size(), ">");
        }
        pos += strlen(vecPrefix);
    }

    // Strip ", 0" trailing template parameter (e.g. SFINAE defaults)
    pos = 0;
    while ((pos = name.find(", 0>", pos)) != std::string::npos) {
        name.erase(pos, 3);
    }

    return name;
}

// Demangle a C++ symbol name. Returns the original if demangling fails.
inline std::string demangle(const char* name) {
    int status = 0;
    char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::string result = simplifyTypeName(demangled);
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
