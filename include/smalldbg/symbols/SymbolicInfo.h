// SmallDBG — what is known about an address
#pragma once

#include "../Types.h"
#include <cstdint>
#include <string>

namespace smalldbg {

// Coarse on purpose: enough to decide how to render or walk something. A
// dialect needing finer distinctions puts them in the name.
enum class SymbolKind {
    Unknown,
    Code,          // instructions
    Data,          // a value, a global, a table
    Segment,       // a broad region: a module's section, a GC space
    ObjectHeader,  // the bookkeeping in front of an object
    Object,        // an object's body
};

// Answers covering one address are ordered, not competing: "the object heap"
// stays true when a finer one says "class Foo". The most precise wins.
enum class SymbolLayer {
    Segment  = 0,   // the broadest thing covering the address
    Analysis = 1,   // derived by inspecting the target
    Symbol   = 2,   // stated by a symbol file or the image itself
    User     = 3,   // stated by the person at the keyboard
};

// Where a name came from, and what a selective flush is keyed on.
struct SourceRef {
    uint32_t id{0};
    bool valid() const { return id != 0; }
    bool operator==(const SourceRef& o) const { return id == o.id; }
};

// A unit of code that names addresses: a mapped native image, or something
// the VM treats as one. Neither is more real than the other.
struct ModuleRef {
    uint32_t id{0};
    bool valid() const { return id != 0; }
    bool operator==(const ModuleRef& o) const { return id == o.id; }
};

enum class ModuleKind { Native, Image };

// How long a source's entries stay true, so dropping the stale ones when the
// heap moves is one call rather than every dialect tracking its own.
enum class Volatility {
    Stable,       // survives everything short of detaching
    UntilResume,  // true only while the target is stopped
    UntilGC,      // survives stepping, not a collection
};

// One thing known about a range of addresses.
struct SymbolicInfo {
    Address     start{0};
    uint64_t    size{0};        // 0 when the extent is unknown
    std::string name;
    SymbolKind  kind{SymbolKind::Unknown};
    SymbolLayer layer{SymbolLayer::Symbol};
    ModuleRef   module;
    SourceRef   source;

    bool covers(Address address) const {
        return address >= start && (size == 0 ? address == start
                                              : address - start < size);
    }
    uint64_t offsetFrom(Address address) const { return address - start; }
};

} // namespace smalldbg
