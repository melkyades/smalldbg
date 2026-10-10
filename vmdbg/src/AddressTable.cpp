#include "AddressTable.h"

#include <cstdio>

namespace vmdbg {

std::string labelWithOffset(const std::string& name, uint64_t offset) {
    if (offset == 0) return name;
    char text[24];
    std::snprintf(text, sizeof(text), "+0x%llx",
                  static_cast<unsigned long long>(offset));
    return name + text;
}

bool Extent::reaches(uint64_t offset) const {
    switch (reach) {
    case Reach::Bytes:     return offset < amount;
    case Reach::Start:     return offset == 0;
    case Reach::UntilNext: return amount == 0 || offset < amount;
    }
    return false;
}

void AddressTable::add(uint64_t address, std::string label, AddressKind kind,
                       Extent extent) {
    entries.insert_or_assign(address, AddressInfo{std::move(label), kind, extent});
}

void AddressTable::addIfAbsent(uint64_t address, std::string label,
                               AddressKind kind, Extent extent) {
    entries.try_emplace(address, AddressInfo{std::move(label), kind, extent});
}

const AddressInfo* AddressTable::lookup(uint64_t address) const {
    auto found = entries.find(address);
    return found == entries.end() ? nullptr : &found->second;
}

uint64_t AddressTable::baseBefore(uint64_t address) const {
    auto after = entries.upper_bound(address);
    if (after == entries.begin()) return 0;
    --after;
    return after->second.extent.reaches(address - after->first) ? after->first : 0;
}

std::string AddressTable::nearestBefore(uint64_t address) const {
    uint64_t base = baseBefore(address);
    if (base == 0) return {};
    const AddressInfo* info = lookup(base);
    return info ? labelWithOffset(info->label, address - base) : std::string();
}

void AddressResolver::define(View view, std::vector<Source> sources) {
    views[view] = std::move(sources);
}

std::string AddressResolver::resolve(uint64_t address, View view) const {
    auto found = views.find(view);
    if (found == views.end()) return tableSource()(address);
    for (const Source& source : found->second) {
        std::string name = source(address);
        if (!name.empty()) return name;
    }
    return {};
}

AddressResolver::Source AddressResolver::tableSource() const {
    return [this](uint64_t address) {
        const AddressInfo* info = addresses.lookup(address);
        return info ? info->label : std::string();
    };
}

} // namespace vmdbg
