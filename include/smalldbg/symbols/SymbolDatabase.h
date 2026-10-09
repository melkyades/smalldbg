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
    /** Returns the module containing `address`, native or in-image, or an
     *  empty reference when no module holds it. **/
    ModuleRef moduleAt(Address address) const;

    // ---- content -------------------------------------------------------
    void add(SymbolicInfo info);
    /** Adds a named extent within a module. **/
    void add(Address start, uint64_t size, const std::string& name,
             SymbolKind kind, SymbolLayer layer, SourceRef source,
             ModuleRef module = {});

    // ---- queries -------------------------------------------------------
    /** Returns the most precise entry covering `address`: the highest layer,
     *  and among equals the tightest extent. Returns nothing when none does. **/
    std::optional<SymbolicInfo> symbolicInfoFor(Address address) const;
    /** Returns every entry covering `address`, coarsest first. **/
    std::vector<SymbolicInfo> allSymbolicInfoFor(Address address) const;
    /** Returns the broadest entry covering `address`, which is the segment
     *  it lies in, or nothing when none covers it. **/
    std::optional<SymbolicInfo> segmentAt(Address address) const;
    /** Returns every entry whose name matches exactly. Names are not unique
     *  across sources. **/
    std::vector<SymbolicInfo> find(const std::string& name) const;
    /** Entries whose name matches `pattern`, where `*` is any run of
     *  characters and `?` any one, ignoring case. A pattern with a `!` is
     *  matched against "module!name"; an entry outside every module goes by
     *  the source that added it. **/
    std::vector<SymbolicInfo> findMatching(const std::string& pattern) const;

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
