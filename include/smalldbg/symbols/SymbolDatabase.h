// SmallDBG — the store everything known about addresses goes into
#pragma once

#include "SymbolicInfo.h"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace smalldbg {

// One place that answers "what is at this address".
//
// Symbols from a pdb, exports, whatever the image itself knows, analysis of
// the heap, and labels typed by hand all end up here, described the same way.
// A caller asks once and gets an answer it can act on without knowing which of
// those produced it.
//
// Entries may overlap: a segment covering a megabyte and a class covering
// forty bytes are both true. They are ordered by layer rather than made to
// compete, so the precise answer wins by default and the whole stack is still
// available to a caller that wants it.
class SymbolDatabase {
public:
    // ---- registration --------------------------------------------------
    //
    // A source names whoever is contributing, and how long its entries stay
    // true. Everything it adds can be dropped in one call, which is what makes
    // naming a moving heap safe.
    SourceRef addSource(const std::string& name, Volatility volatility);
    std::string sourceName(SourceRef source) const;

    ModuleRef addModule(const std::string& name, ModuleKind kind,
                        Address start, Address end);
    std::string moduleName(ModuleRef module) const;
    ModuleKind moduleKind(ModuleRef module) const;
    /// The module containing an address, native or in-image.
    ModuleRef moduleAt(Address address) const;

    // ---- content -------------------------------------------------------
    void add(SymbolicInfo info);
    /// Convenience for the common case of a named extent within a module.
    void add(Address start, uint64_t size, const std::string& name,
             SymbolKind kind, SymbolLayer layer, SourceRef source,
             ModuleRef module = {});

    // ---- queries -------------------------------------------------------
    /// The most precise thing covering `address`: highest layer, and among
    /// equals the tightest extent.
    std::optional<SymbolicInfo> symbolicInfoFor(Address address) const;
    /// Everything covering `address`, coarsest first.
    std::vector<SymbolicInfo> allSymbolicInfoFor(Address address) const;
    /// The broadest thing covering `address` -- the segment it lives in --
    /// kept separate so a caller after context does not have to filter.
    std::optional<SymbolicInfo> segmentAt(Address address) const;
    /// Entries whose name matches exactly. Names are not unique across
    /// sources, so this answers all of them.
    std::vector<SymbolicInfo> find(const std::string& name) const;

    // ---- invalidation --------------------------------------------------
    //
    // A collection moves everything that is not pinned, so the names for it
    // stop being true at a moment the database can be told about rather than
    // has to detect.
    void invalidate(Volatility volatility);
    void invalidate(SourceRef source);
    void invalidate(Address start, Address end);
    void clear();

    size_t size() const { return entries.size(); }

private:
    struct SourceRecord {
        std::string name;
        Volatility volatility{Volatility::Stable};
    };
    struct ModuleRecord {
        std::string name;
        ModuleKind kind{ModuleKind::Native};
        Address start{0};
        Address end{0};
    };

    // Keyed by start address; several entries can share one, so a multimap.
    // Lookup walks back from the first entry starting after the address,
    // which bounds the scan by how far the widest entry reaches.
    std::multimap<Address, SymbolicInfo> entries;
    std::vector<SourceRecord> sources;
    std::vector<ModuleRecord> modules;
    Address widestExtent{0};
};

} // namespace smalldbg
