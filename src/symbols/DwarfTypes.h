// DWARF type information database — parses .debug_info from .o files
// referenced by N_OSO stab entries in Mach-O binaries to extract C/C++
// struct/class layout and global variable type associations.
#pragma once

#include "../../include/smalldbg/SymbolProvider.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>

namespace smalldbg {

/// Parsed DWARF type database for one or more compilation units.
class DwarfTypeDatabase {
public:
    /// Parse DWARF types from .o files referenced by a Mach-O binary.
    void loadFromBinary(const std::string& binaryPath);

    /// Look up a type by fully-qualified name (e.g. "Egg::Runtime").
    const NativeTypeInfo* findType(const std::string& name) const;

    /// Get the type name of a global variable by its demangled symbol name.
    std::optional<std::string> getVariableTypeName(const std::string& name) const;

    bool isLoaded() const { return loaded; }

private:
    bool loaded{false};

    // Type database: qualified name → type info
    std::unordered_map<std::string, NativeTypeInfo> types;

    // Variable type map: demangled symbol name → type name
    std::unordered_map<std::string, std::string> variableTypes;

    // Parse a single .o file's DWARF sections
    void parseObjectFile(const std::string& path);

    // Parse an .o member extracted from an .a archive
    void parseArchiveMember(const std::string& archivePath,
                            const std::string& memberName);

    // Parse DWARF from memory-mapped Mach-O object file data
    void parseDwarfFromObject(const uint8_t* base, size_t size);
};

} // namespace smalldbg
