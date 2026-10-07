#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace vmdbg {

// What kind of thing an address turned out to be.
enum class AddressKind {
    Method,     // entry point of code the VM generated
    Class,      // a class object
    Dispatch,   // a method lookup table, or the array of them
    Runtime,    // an entry in the VM's own routine table
    WellKnown,  // objects the VM names directly, such as its constants
};

/** "name" at its start, "name+0xNN" anywhere inside it. **/
std::string labelWithOffset(const std::string& name, uint64_t offset);

/** How far a labelled thing reaches from its start, which decides what an
 *  address after the start reads as. **/
class Extent {
public:
    /** Exactly `size` bytes. **/
    static Extent bytes(uint64_t size) { return Extent(Reach::Bytes, size); }

    /** A size that is not known, so only the start is known to be it. **/
    static Extent unknown() { return Extent(Reach::Start, 0); }

    /** Up to the next label, and no further than `limit` bytes when one is
     *  given: what code laid out back to back looks like. **/
    static Extent untilNext(uint64_t limit = 0) { return Extent(Reach::UntilNext, limit); }

    /** Returns true when an address `offset` bytes past the start is still
     *  this thing. The next label, when there is one, is past `offset`. **/
    bool reaches(uint64_t offset) const;

private:
    enum class Reach { Bytes, Start, UntilNext };
    Extent(Reach reach, uint64_t amount) : reach(reach), amount(amount) {}

    Reach reach;
    uint64_t amount;  // the size, or the limit; 0 for no limit
};

struct AddressInfo {
    std::string label;
    AddressKind kind;
    Extent extent;
};

/** What lives at an address inside a VM's own memory.
 *
 *  Generated code, dispatch tables and class objects belong to no module, so
 *  a native symbol provider has nothing to say about them. A VM indexes them
 *  from its own walk of the heap; the index and the lookups over it are here.
 **/
class AddressTable {
public:
    void clear() { entries.clear(); }
    size_t size() const { return entries.size(); }

    void add(uint64_t address, std::string label, AddressKind kind, Extent extent);

    /** Keeps what is already there, so a thing reached twice through different
     *  paths keeps the name the first walk gave it. **/
    void addIfAbsent(uint64_t address, std::string label, AddressKind kind,
                     Extent extent);

    /** The entry starting exactly at `address`. Returns null when none does.
     **/
    const AddressInfo* lookup(uint64_t address) const;

    /** Returns the start of the entry that reaches `address`, or 0 when none
     *  does. Only the nearest entry at or before it is asked, so a label
     *  inside a larger thing hides that thing from the addresses after it.
     **/
    uint64_t baseBefore(uint64_t address) const;

    /** That entry as "label" or "label+0xNN". Returns an empty string when no
     *  entry reaches `address`. **/
    std::string nearestBefore(uint64_t address) const;

private:
    std::map<uint64_t, AddressInfo> entries;
};

/** What an address is being read as. A jump target wants the code it lands
 *  in, a word loaded or compared wants the object it points at; a VM may
 *  number views of its own from FirstVMView on. **/
using View = int;
constexpr View CodeView = 0;
constexpr View DataView = 1;
constexpr View FirstVMView = 16;

/** Names addresses as a view wants them read. A view is an ordered list of
 *  sources, each a function from an address to a name, and the first source
 *  with a name for an address gives it. A view never defined tries the table
 *  alone. **/
class AddressResolver {
public:
    using Source = std::function<std::string(uint64_t address)>;

    AddressTable& table() { return addresses; }
    const AddressTable& table() const { return addresses; }

    /** Makes `view` try `sources`, in order. **/
    void define(View view, std::vector<Source> sources);

    /** The name `address` has in `view`. Returns an empty string when no
     *  source has one. **/
    std::string resolve(uint64_t address, View view) const;

    /** A source naming an address by the table entry that starts at it. **/
    Source tableSource() const;

private:
    AddressTable addresses;
    std::map<View, std::vector<Source>> views;
};

} // namespace vmdbg
