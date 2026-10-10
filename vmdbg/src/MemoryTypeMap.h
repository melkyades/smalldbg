#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace vmdbg {

/** A MemType says how a stretch of target memory is shown in a listing. **/
enum class MemType {
    Code,
    Data1,
    Data2,
    Data4,
    Data8,
    StringAscii,
    StringUtf16,
    StringUtf32,
    Struct,   // a layout the dialect defined; MemTypeRange::structId says which
};

const char* memTypeName(MemType t);
std::optional<MemType> memTypeFromName(const std::string& name);

/** Returns the bytes one element occupies: 1 for Code, and 0 for Struct,
 *  whose size only the map knows. **/
size_t memTypeElementSize(MemType t);

/** A StructType is a named layout over memory, such as an object header or
 *  a VM record. The map only keeps the name and the size; what the fields
 *  mean stays with whoever defined it. **/
struct StructType {
    std::string name;
    size_t size{0};   // 0 when instances vary and only the provider knows
};

struct MemTypeRange {
    uint64_t start{0};
    uint64_t end{0};      // exclusive
    MemType  type{MemType::Data1};
    bool     user{false}; // set by the user rather than derived
    int      structId{-1};
};

/** A MemoryTypeMap says what type each address has. A user override wins,
 *  then a provider, then the defaults derived from the memory map, then a
 *  fallback. Ranges are half-open and do not overlap within a layer;
 *  adding one splits or replaces what was there. **/
class MemoryTypeMap {
public:
    /** A Provider answers one address at a time, for runs too small or too
     *  many to keep as ranges. It returns false to let the defaults answer. **/
    using Provider = std::function<bool(uint64_t addr, MemTypeRange& out)>;
    void setProvider(Provider p) { provider = std::move(p); }

    /** Names a layout and returns its id. Defining a name again returns the
     *  existing id, so a layout can be defined on demand. **/
    int defineStruct(const std::string& name, size_t size);
    const StructType* structType(int id) const;
    int structIdNamed(const std::string& name) const;
    const std::vector<StructType>& structTypes() const { return structs; }

    /** Returns the name to show for `range`, looking a struct up by its id. **/
    std::string typeName(const MemTypeRange& range) const;
    /** Returns the bytes one element of `range` occupies, looking a struct up
     *  by its id. **/
    size_t elementSize(const MemTypeRange& range) const;

    void setDefault(uint64_t start, uint64_t end, MemType type, int structId = -1);
    void clearDefaults();

    void setUser(uint64_t start, uint64_t end, MemType type, int structId = -1);
    void clearUser(uint64_t start, uint64_t end);
    void clearAllUser();

    void setFallback(MemType t) { fallback = t; }
    MemType getFallback() const { return fallback; }

    MemType typeAt(uint64_t addr) const;
    bool isUserTyped(uint64_t addr) const;

    /** Returns the effective range containing `addr`, clipped to [lo, hi). **/
    MemTypeRange rangeAt(uint64_t addr, uint64_t lo, uint64_t hi) const;

    /** Returns [start, end) split into maximal runs of one effective type. **/
    std::vector<MemTypeRange> classify(uint64_t start, uint64_t end) const;

    const std::map<uint64_t, MemTypeRange>& userRanges() const { return user; }
    const std::map<uint64_t, MemTypeRange>& defaultRanges() const { return defaults; }

private:
    // keyed by range start
    std::map<uint64_t, MemTypeRange> defaults;
    std::map<uint64_t, MemTypeRange> user;
    std::vector<StructType> structs;   // indexed by struct id
    Provider provider;
    MemType fallback{MemType::Data1};

    uint64_t nextUserStart(uint64_t addr, uint64_t hi) const;

    static void insert(std::map<uint64_t, MemTypeRange>& into,
                       uint64_t start, uint64_t end, MemType type, bool user,
                       int structId);
    static void erase(std::map<uint64_t, MemTypeRange>& from,
                      uint64_t start, uint64_t end);
    static const MemTypeRange* find(const std::map<uint64_t, MemTypeRange>& in,
                                    uint64_t addr);
};

} // namespace vmdbg
