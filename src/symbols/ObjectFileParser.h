// Abstract interface for parsing object files to extract symbol tables.
// Platform implementations: MachOParser (macOS), ElfParser (Linux).
#pragma once

#include "SymbolsInternal.h"
#include "platform/Platform.h"
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

    // Reads where the image loaded at `loadAddress` ends, out of the
    // target's memory. Returns false when the parser cannot read images
    // there, and the module is then read from its file.
    virtual bool readLoadedExtent(const smalldbg_internal::MemoryReader& read,
                                  Address loadAddress, ModuleSymbols& out) {
        (void)read; (void)loadAddress; (void)out;
        return false;
    }

    // Reads the symbols of the image loaded at `loadAddress` out of the
    // target's memory. Returns false when they cannot be read there.
    virtual bool parseLoadedSymbols(const smalldbg_internal::MemoryReader& read,
                                    Address loadAddress, ModuleSymbols& out) {
        (void)read; (void)loadAddress; (void)out;
        return false;
    }

    // Factory: creates the platform-appropriate parser.
    static std::unique_ptr<ObjectFileParser> create();
};

} // namespace smalldbg
