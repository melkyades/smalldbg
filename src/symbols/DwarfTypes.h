// DWARF type information database — parses .debug_info from .o files
// referenced by N_OSO stab entries in Mach-O binaries to extract C/C++
// struct/class layout and global variable type associations, plus
// subprogram local variable / parameter locations.
#pragma once

#include "../../include/smalldbg/symbols/SymbolProvider.h"
#include "../../include/smalldbg/Types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>

namespace smalldbg {

/** A DwarfVariable is a local variable or parameter read from DWARF. **/
struct DwarfVariable {
    std::string name;
    std::string typeName;
    uint64_t typeSize{0};
    VariableLocation locationType{VariableLocation::Unknown};
    int64_t locationOffset{0};   // offset for FrameRelative/StackRelative
    uint32_t dwarfRegNum{0};     // DWARF register number (for Register type)
    bool isParameter{false};
};

/** A DwarfSubprogram is a function with its address range and locals. **/
struct DwarfSubprogram {
    std::string name;
    uint64_t lowPC{0};
    uint64_t highPC{0};          // absolute high PC (lowPC + length or raw)
    std::vector<DwarfVariable> variables;
};

/** A DwarfTypeDatabase holds the types parsed from one or more compilation
 *  units. **/
class DwarfTypeDatabase {
public:
    /** Parses the types in the .o files a Mach-O binary refers to, or those
     *  in an ELF binary's own DWARF sections. **/
    void loadFromBinary(const std::string& binaryPath);

    /** Returns the type with a fully qualified name such as "MyApp::Runtime",
     *  or null when there is none. It lives as long as the database. **/
    const NativeTypeInfo* findType(const std::string& name) const;

    /** Returns the type name of the global with this demangled name, or
     *  nothing when there is no such global. **/
    std::optional<std::string> getVariableTypeName(const std::string& name) const;

    /** Returns the subprogram containing `pc`, or null when there is none.
     *  It lives as long as the database. **/
    const DwarfSubprogram* findSubprogram(uint64_t pc) const;

    /** Returns the subprogram with this demangled name, or null when there is
     *  none. It lives as long as the database. **/
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

    // Parse the DWARF sections of a single .o file, or of an ELF image
    void parseObjectFile(const std::string& path);

    // Parse an .o member extracted from an .a archive
    void parseArchiveMember(const std::string& archivePath,
                            const std::string& memberName);

    // Parse DWARF from a memory-mapped Mach-O object file or ELF image
    void parseDwarfFromObject(const uint8_t* base, size_t size);
};

} // namespace smalldbg
