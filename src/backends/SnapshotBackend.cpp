#include "SnapshotBackend.h"

#include <algorithm>
#include <fstream>

namespace smalldbg {

// Every region is read in when the snapshot is opened, so a missing or short
// file is reported once, there, rather than as a failed read later on.
Status SnapshotBackend::openSnapshot(const std::vector<SnapshotRegion>& given) {
    if (opened) return Status::AlreadyAttached;

    std::vector<Region> loaded;
    for (const auto& region : given) {
        Region into{region.address, {}};
        Status status = load(region, into);
        if (status != Status::Ok) return status;
        if (!into.bytes.empty()) loaded.push_back(std::move(into));
    }

    std::sort(loaded.begin(), loaded.end(),
              [](const Region& a, const Region& b) { return a.address < b.address; });
    for (size_t i = 1; i < loaded.size(); i++) {
        if (loaded[i - 1].end() <= loaded[i].address) continue;
        if (log) log("(snapshot) regions overlap at " + std::to_string(loaded[i].address));
        return Status::Error;
    }

    regions = std::move(loaded);
    opened = true;
    initProcess(0);
    return Status::Ok;
}

// Returns NotFound when the file cannot be opened, and Error when it ends
// before the region does.
Status SnapshotBackend::load(const SnapshotRegion& given, Region& into) const {
    if (given.file.empty()) {
        into.bytes = given.bytes;
        return Status::Ok;
    }
    std::ifstream file(given.file, std::ios::binary);
    if (!file) {
        if (log) log("(snapshot) cannot open " + given.file);
        return Status::NotFound;
    }
    into.bytes.resize(given.size);
    file.seekg(static_cast<std::streamoff>(given.fileOffset));
    file.read(reinterpret_cast<char*>(into.bytes.data()),
              static_cast<std::streamsize>(given.size));
    if (static_cast<uint64_t>(file.gcount()) == given.size) return Status::Ok;
    if (log) log("(snapshot) " + given.file + " ends before the region does");
    return Status::Error;
}

Status SnapshotBackend::attach(uintptr_t) { return Status::NotSupported; }

Status SnapshotBackend::launch(const std::string&, const std::vector<std::string>&) {
    return Status::NotSupported;
}

Status SnapshotBackend::detach() {
    regions.clear();
    opened = false;
    process.reset();
    return Status::Ok;
}

const SnapshotBackend::Region* SnapshotBackend::regionAt(Address address) const {
    auto after = std::upper_bound(regions.begin(), regions.end(), address,
        [](Address at, const Region& region) { return at < region.address; });
    if (after == regions.begin()) return nullptr;
    const Region& region = *(after - 1);
    return address < region.end() ? &region : nullptr;
}

// A read may cross from one region into the next when they are adjacent. It
// fails as a whole, leaving `outBuf` untouched, when any byte is missing.
Status SnapshotBackend::readMemory(Address address, void* outBuf, size_t size) const {
    for (Address at = address; at < address + size;) {
        const Region* region = regionAt(at);
        if (!region) return Status::Error;
        at = region->end();
    }

    auto* out = static_cast<uint8_t*>(outBuf);
    for (Address at = address; at < address + size;) {
        const Region* region = regionAt(at);
        size_t count = static_cast<size_t>(std::min<Address>(region->end(), address + size) - at);
        auto from = region->bytes.begin() + static_cast<std::ptrdiff_t>(at - region->address);
        out = std::copy(from, from + static_cast<std::ptrdiff_t>(count), out);
        at += count;
    }
    return Status::Ok;
}

} // namespace smalldbg
