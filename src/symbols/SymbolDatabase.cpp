#include "smalldbg/symbols/SymbolDatabase.h"

#include <algorithm>

namespace smalldbg {

namespace {

// Ids are one-based so that a default-constructed ref is "none".
uint32_t indexOf(uint32_t id) { return id - 1; }

// Which of two answers a caller should be given when both cover an address.
// The later layer wins; between equals the tighter extent does, since it says
// more. An entry with no extent is a point, which is as tight as it gets.
bool isBetterThan(const SymbolicInfo& candidate, const SymbolicInfo& current) {
    if (candidate.layer != current.layer) return candidate.layer > current.layer;
    if (candidate.size != current.size) {
        if (candidate.size == 0) return true;
        if (current.size == 0) return false;
        return candidate.size < current.size;
    }
    return candidate.start > current.start;
}

} // namespace

SourceRef SymbolDatabase::addSource(const std::string& name, Volatility volatility) {
    sources.push_back({name, volatility});
    return SourceRef{static_cast<uint32_t>(sources.size())};
}

std::string SymbolDatabase::sourceName(SourceRef source) const {
    if (!source.valid() || indexOf(source.id) >= sources.size()) return {};
    return sources[indexOf(source.id)].name;
}

ModuleRef SymbolDatabase::addModule(const std::string& name, ModuleKind kind,
                                    Address start, Address end) {
    modules.push_back({name, kind, start, end});
    return ModuleRef{static_cast<uint32_t>(modules.size())};
}

std::string SymbolDatabase::moduleName(ModuleRef module) const {
    if (!module.valid() || indexOf(module.id) >= modules.size()) return {};
    return modules[indexOf(module.id)].name;
}

ModuleKind SymbolDatabase::moduleKind(ModuleRef module) const {
    if (!module.valid() || indexOf(module.id) >= modules.size())
        return ModuleKind::Native;
    return modules[indexOf(module.id)].kind;
}

ModuleRef SymbolDatabase::moduleAt(Address address) const {
    for (size_t i = 0; i < modules.size(); i++)
        if (address >= modules[i].start && address < modules[i].end)
            return ModuleRef{static_cast<uint32_t>(i + 1)};
    return {};
}

void SymbolDatabase::add(SymbolicInfo info) {
    // The widest entry bounds how far back a lookup has to walk, so it is
    // tracked as entries arrive rather than rediscovered on every query.
    widestExtent = std::max(widestExtent, info.size);
    entries.emplace(info.start, std::move(info));
}

void SymbolDatabase::add(Address start, uint64_t size, const std::string& name,
                         SymbolKind kind, SymbolLayer layer, SourceRef source,
                         ModuleRef module) {
    SymbolicInfo info;
    info.start = start;
    info.size = size;
    info.name = name;
    info.kind = kind;
    info.layer = layer;
    info.source = source;
    info.module = module.valid() ? module : moduleAt(start);
    add(std::move(info));
}

std::optional<SymbolicInfo> SymbolDatabase::symbolicInfoFor(Address address) const {
    std::optional<SymbolicInfo> best;
    // Everything covering `address` starts at or before it, and no earlier
    // than the widest extent behind it.
    auto it = entries.upper_bound(address);
    const Address floor = address >= widestExtent ? address - widestExtent : 0;
    while (it != entries.begin()) {
        --it;
        if (it->first < floor) break;
        if (!it->second.covers(address)) continue;
        if (!best || isBetterThan(it->second, *best)) best = it->second;
    }
    return best;
}

std::vector<SymbolicInfo> SymbolDatabase::allSymbolicInfoFor(Address address) const {
    std::vector<SymbolicInfo> found;
    auto it = entries.upper_bound(address);
    const Address floor = address >= widestExtent ? address - widestExtent : 0;
    while (it != entries.begin()) {
        --it;
        if (it->first < floor) break;
        if (it->second.covers(address)) found.push_back(it->second);
    }
    std::sort(found.begin(), found.end(),
              [](const SymbolicInfo& a, const SymbolicInfo& b) {
                  return isBetterThan(b, a);
              });
    return found;
}

std::optional<SymbolicInfo> SymbolDatabase::segmentAt(Address address) const {
    std::optional<SymbolicInfo> best;
    for (const auto& info : allSymbolicInfoFor(address)) {
        if (info.kind != SymbolKind::Segment) continue;
        if (!best || info.size > best->size) best = info;
    }
    return best;
}

std::vector<SymbolicInfo> SymbolDatabase::find(const std::string& name) const {
    std::vector<SymbolicInfo> found;
    for (const auto& [start, info] : entries)
        if (info.name == name) found.push_back(info);
    return found;
}

void SymbolDatabase::invalidate(Volatility volatility) {
    for (auto it = entries.begin(); it != entries.end();) {
        const auto& source = it->second.source;
        bool drop = source.valid() && indexOf(source.id) < sources.size() &&
                    sources[indexOf(source.id)].volatility == volatility;
        it = drop ? entries.erase(it) : std::next(it);
    }
}

void SymbolDatabase::invalidate(SourceRef source) {
    for (auto it = entries.begin(); it != entries.end();)
        it = it->second.source == source ? entries.erase(it) : std::next(it);
}

void SymbolDatabase::invalidate(Address start, Address end) {
    for (auto it = entries.begin(); it != entries.end();) {
        const auto& info = it->second;
        Address last = info.start + (info.size ? info.size : 1);
        bool overlaps = info.start < end && last > start;
        it = overlaps ? entries.erase(it) : std::next(it);
    }
}

void SymbolDatabase::clear() {
    entries.clear();
    widestExtent = 0;
}

} // namespace smalldbg
