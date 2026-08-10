#include "MemoryTypeMap.h"

#include <algorithm>

namespace webside {

const char* memTypeName(MemType t) {
    switch (t) {
    case MemType::Code:        return "code";
    case MemType::Data1:       return "data1";
    case MemType::Data2:       return "data2";
    case MemType::Data4:       return "data4";
    case MemType::Data8:       return "data8";
    case MemType::StringAscii: return "ascii";
    case MemType::StringUtf16: return "utf16";
    case MemType::StringUtf32: return "utf32";
    }
    return "data1";
}

std::optional<MemType> memTypeFromName(const std::string& name) {
    if (name == "code")  return MemType::Code;
    if (name == "data1") return MemType::Data1;
    if (name == "data2") return MemType::Data2;
    if (name == "data4") return MemType::Data4;
    if (name == "data8") return MemType::Data8;
    if (name == "ascii") return MemType::StringAscii;
    if (name == "utf16") return MemType::StringUtf16;
    if (name == "utf32") return MemType::StringUtf32;
    return std::nullopt;
}

size_t memTypeElementSize(MemType t) {
    switch (t) {
    case MemType::Code:        return 1;
    case MemType::Data1:       return 1;
    case MemType::Data2:       return 2;
    case MemType::Data4:       return 4;
    case MemType::Data8:       return 8;
    case MemType::StringAscii: return 1;
    case MemType::StringUtf16: return 2;
    case MemType::StringUtf32: return 4;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Range bookkeeping
// ---------------------------------------------------------------------------

void MemoryTypeMap::erase(std::map<uint64_t, MemTypeRange>& from,
                          uint64_t start, uint64_t end) {
    if (end <= start) return;

    // Trim or split whatever overlaps [start, end).
    auto it = from.upper_bound(start);
    if (it != from.begin()) --it;

    std::vector<MemTypeRange> reinsert;
    while (it != from.end() && it->second.start < end) {
        const MemTypeRange r = it->second;
        if (r.end <= start) { ++it; continue; }

        it = from.erase(it);
        if (r.start < start)
            reinsert.push_back({r.start, start, r.type, r.user});
        if (r.end > end)
            reinsert.push_back({end, r.end, r.type, r.user});
    }
    for (const auto& r : reinsert) from[r.start] = r;
}

void MemoryTypeMap::insert(std::map<uint64_t, MemTypeRange>& into,
                           uint64_t start, uint64_t end, MemType type, bool user) {
    if (end <= start) return;
    erase(into, start, end);
    into[start] = MemTypeRange{start, end, type, user};
}

const MemTypeRange* MemoryTypeMap::find(const std::map<uint64_t, MemTypeRange>& in,
                                        uint64_t addr) {
    if (in.empty()) return nullptr;
    auto it = in.upper_bound(addr);
    if (it == in.begin()) return nullptr;
    --it;
    if (addr >= it->second.start && addr < it->second.end) return &it->second;
    return nullptr;
}

void MemoryTypeMap::setDefault(uint64_t start, uint64_t end, MemType type) {
    insert(defaults, start, end, type, false);
}

void MemoryTypeMap::clearDefaults() { defaults.clear(); }

void MemoryTypeMap::setUser(uint64_t start, uint64_t end, MemType type) {
    insert(user, start, end, type, true);
}

void MemoryTypeMap::clearUser(uint64_t start, uint64_t end) {
    erase(user, start, end);
}

void MemoryTypeMap::clearAllUser() { user.clear(); }

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

MemType MemoryTypeMap::typeAt(uint64_t addr) const {
    if (const auto* u = find(user, addr)) return u->type;
    MemTypeRange p;
    if (provider && provider(addr, p)) return p.type;
    if (const auto* d = find(defaults, addr)) return d->type;
    return fallback;
}

bool MemoryTypeMap::isUserTyped(uint64_t addr) const {
    return find(user, addr) != nullptr;
}

uint64_t MemoryTypeMap::nextUserStart(uint64_t addr, uint64_t hi) const {
    auto it = user.upper_bound(addr);
    return it == user.end() ? hi : std::min(hi, it->second.start);
}

// A user override wins outright; otherwise the provider, then the defaults.
// Every answer is clipped to the next user range so classify() can walk with
// this alone and never step over a layer it should have seen.
MemTypeRange MemoryTypeMap::rangeAt(uint64_t addr, uint64_t lo, uint64_t hi) const {
    if (const auto* u = find(user, addr))
        return {std::max(lo, u->start), std::min(hi, u->end), u->type, true};

    uint64_t clip = nextUserStart(addr, hi);

    MemTypeRange p;
    if (provider && provider(addr, p))
        return {std::max(lo, p.start), std::min(clip, p.end), p.type, false};

    if (const auto* d = find(defaults, addr))
        return {std::max(lo, d->start), std::min(clip, d->end), d->type, false};

    auto dit = defaults.upper_bound(addr);
    if (dit != defaults.end()) clip = std::min(clip, dit->second.start);
    return {lo, clip, fallback, false};
}

std::vector<MemTypeRange> MemoryTypeMap::classify(uint64_t start, uint64_t end) const {
    std::vector<MemTypeRange> out;
    if (end <= start) return out;

    uint64_t at = start;
    while (at < end) {
        MemTypeRange r = rangeAt(at, at, end);
        uint64_t next = (r.end > at && r.end <= end) ? r.end : end;

        if (!out.empty() && out.back().type == r.type && out.back().user == r.user
            && out.back().end == at) {
            out.back().end = next;
        } else {
            out.push_back({at, next, r.type, r.user});
        }
        at = next;
    }
    return out;
}

} // namespace webside
