#pragma once

#include "Types.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace smalldbg {

/** A range of memory a snapshot holds: bytes that appear at `address` in the
 *  target, read from a file or given as they are.
 *
 *  Laying a snapshot out is the business of whoever knows its format: a
 *  reader for an image or a VM's own dump says where each piece goes, and the
 *  debugger only reads the pieces back. **/
struct SnapshotRegion {
    Address address{0};
    std::string file;          // empty when `bytes` holds the contents
    uint64_t fileOffset{0};
    uint64_t size{0};
    std::vector<uint8_t> bytes;

    /** `size` bytes of `file`, from `offset` on, appearing at `address`. **/
    static SnapshotRegion fromFile(Address address, std::string file,
                                   uint64_t offset, uint64_t size) {
        SnapshotRegion region;
        region.address = address;
        region.file = std::move(file);
        region.fileOffset = offset;
        region.size = size;
        return region;
    }

    /** `bytes`, appearing at `address`. **/
    static SnapshotRegion fromBytes(Address address, std::vector<uint8_t> bytes) {
        SnapshotRegion region;
        region.address = address;
        region.size = bytes.size();
        region.bytes = std::move(bytes);
        return region;
    }
};

} // namespace smalldbg
