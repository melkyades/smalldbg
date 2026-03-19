// DWARF type information database — parses .debug_info from .o files
// referenced by N_OSO stab entries in Mach-O binaries to extract C/C++
// struct/class layout and global variable type associations, plus
// subprogram local variable / parameter locations.
#pragma once

#include "../../include/smalldbg/SymbolProvider.h"
#include "../../include/smalldbg/Types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>

namespace smalldbg {

/// A local variable or formal parameter extracted from DWARF.
struct DwarfVariable {
    std::string name;
    std::string typeName;
    uint64_t typeSize{0};
    VariableLocation locationType{VariableLocation::Unknown};
    int64_t locationOffset{0};   // offset for FrameRelative/StackRelative
    uint32_t dwarfRegNum{0};     // DWARF register number (for Register type)
    bool isParameter{false};
};

/// A subprogram (function) with its address range and local variables.
struct DwarfSubprogram {
    std::string name;
    uint64_t lowPC{0};
    uint64_t highPC{0};          // absolute high PC (lowPC + length or raw)
    std::vector<DwarfVariable> variables;
};

/// Parsed DWARF type database for one or more compilation units.
class DwarfTypeDatabase {
public:
    /// Parse DWARF types from .o files referenced by a Mach-O binary.
    void loadFromBinary(const std::string& binaryPath);

    /// Look up a type by fully-qualified name (e.g. "MyApp::Runtime").
    const NativeTypeInfo* findType(const std::string& name) const;

    /// Get the type name of a global variable by its demangled symbol name.
    std::optional<std::string> getVariableTypeName(const std::string& name) const;

    /// Find the subprogram containing the given PC address.
    const DwarfSubprogram* findSubprogram(uint64_t pc) const;

    /// Find a subprogram by demangled function name.
    const DwarfSubprogram* findSubprogramByName(const std::string& name) const;

    bool isLoaded() const { return loaded; }

private:
    bool loaded{false};

    // Type database: qualified name → type info
    std::unordered_map<std::string, NativeTypeInfo> types;

    // Variable type map: demangled symbol name → type name
    std::unordered_map<std::string, std::string> variableTypes;

    // Subprogram database: address-range indexed
    std::vector<DwarfSubprogram> subprograms;

    // Parse a single .o file's DWARF sections
    void parseObjectFile(const std::string& path);

    // Parse an .o member extracted from an .a archive
    void parseArchiveMember(const std::string& archivePath,
                            const std::string& memberName);

    // Parse DWARF from memory-mapped Mach-O object file data
    void parseDwarfFromObject(const uint8_t* base, size_t size);
};

} // namespace smalldbg
