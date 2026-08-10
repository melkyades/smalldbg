#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace webside {

/// How a stretch of target memory should be presented in a listing.
enum class MemType {
    Code,
    Data1,
    Data2,
    Data4,
    Data8,
    StringAscii,
    StringUtf16,
    StringUtf32,
};

const char* memTypeName(MemType t);
std::optional<MemType> memTypeFromName(const std::string& name);

/// Bytes one element occupies (1 for Code).
size_t memTypeElementSize(MemType t);

struct MemTypeRange {
    uint64_t start{0};
    uint64_t end{0};      // exclusive
    MemType  type{MemType::Data1};
    bool     user{false}; // set by the user rather than derived
};

/// Three-layer address-to-type lookup, mirroring how labels resolve: a user
/// override wins, then a provider, then the defaults derived from the memory
/// map, then a fallback. Ranges are half-open and kept non-overlapping within
/// each layer; inserting an overlapping one splits or replaces what was there.
class MemoryTypeMap {
public:
    /// Answers one address at a time, for runs too fine or too numerous to
    /// materialise as ranges. Returns false to let the defaults answer.
    using Provider = std::function<bool(uint64_t addr, MemTypeRange& out)>;
    void setProvider(Provider p) { provider = std::move(p); }

    void setDefault(uint64_t start, uint64_t end, MemType type);
    void clearDefaults();

    void setUser(uint64_t start, uint64_t end, MemType type);
    void clearUser(uint64_t start, uint64_t end);
    void clearAllUser();

    void setFallback(MemType t) { fallback = t; }
    MemType getFallback() const { return fallback; }

    MemType typeAt(uint64_t addr) const;
    bool isUserTyped(uint64_t addr) const;

    /// Effective range containing `addr`, clipped to [lo, hi).
    MemTypeRange rangeAt(uint64_t addr, uint64_t lo, uint64_t hi) const;

    /// Split [start, end) into maximal runs of a single effective type.
    std::vector<MemTypeRange> classify(uint64_t start, uint64_t end) const;

    const std::map<uint64_t, MemTypeRange>& userRanges() const { return user; }
    const std::map<uint64_t, MemTypeRange>& defaultRanges() const { return defaults; }

private:
    // keyed by range start
    std::map<uint64_t, MemTypeRange> defaults;
    std::map<uint64_t, MemTypeRange> user;
    Provider provider;
    MemType fallback{MemType::Data1};

    uint64_t nextUserStart(uint64_t addr, uint64_t hi) const;

    static void insert(std::map<uint64_t, MemTypeRange>& into,
                       uint64_t start, uint64_t end, MemType type, bool user);
    static void erase(std::map<uint64_t, MemTypeRange>& from,
                      uint64_t start, uint64_t end);
    static const MemTypeRange* find(const std::map<uint64_t, MemTypeRange>& in,
                                    uint64_t addr);
};

} // namespace webside
