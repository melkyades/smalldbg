// Abstract interface for parsing object files to extract symbol tables.
// Platform implementations: MachOParser (macOS), ElfParser (Linux).
#pragma once

#include "SymbolsInternal.h"
#include <memory>

namespace smalldbg {

class ObjectFileParser {
public:
    virtual ~ObjectFileParser() = default;

    // Parse an object file at `path` and populate `out` with symbols.
    // Addresses are adjusted by `slide` (ASLR offset).
    virtual bool parseFile(const std::string& path, int64_t slide,
                           ModuleSymbols& out) = 0;

    // Compute the ASLR slide for a module by comparing its on-disk
    // text segment address against the runtime load address.
    virtual int64_t computeSlide(const std::string& path,
                                 Address loadAddress) = 0;

    // Factory: creates the platform-appropriate parser.
    static std::unique_ptr<ObjectFileParser> create();
};

} // namespace smalldbg
