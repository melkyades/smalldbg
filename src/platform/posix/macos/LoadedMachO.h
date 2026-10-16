// LoadedMachO: the layout of a Mach-O image as loaded in a process, read
// through that process's memory.
//
// The images of the dyld shared cache, which are nearly all the system's
// libraries, have no file of their own on disk, and a file that does exist
// need not be the build the process loaded. What the process has mapped is
// what it runs, so that is where a live target's images are read from.
#pragma once

#include "platform/Platform.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace smalldbg_internal {

struct LoadedSection {
    std::string name;      // "__TEXT,__text"
    uint64_t start{0};     // slid
    uint64_t end{0};       // exclusive
    bool executable{false};
};

struct LoadedMachO {
    int64_t slide{0};          // load address minus the address __TEXT asks for
    uint64_t textEnd{0};       // end of __TEXT, slid
    std::vector<LoadedSection> sections;

    // The symbol table, where __LINKEDIT is mapped: nlist_64 entries and the
    // string table they index. A shared cache image indexes the cache's
    // string table, which all its images share.
    bool hasSymbols{false};
    uint64_t symbols{0};
    uint32_t symbolCount{0};
    uint64_t strings{0};
    uint32_t stringsSize{0};
};

/** Reads the load commands of the 64-bit image loaded at `base`. Returns false
 *  when there is no such image there. **/
bool readLoadedMachO(const MemoryReader& read, uint64_t base, LoadedMachO& image);

/** A StringTable reads names out of a string table in the target, a block at
 *  a time and only the blocks asked about: a shared cache's table runs to
 *  hundreds of megabytes, of which one image uses a little. **/
class StringTable {
public:
    StringTable(const MemoryReader& read, uint64_t start, uint32_t size)
        : read(read), start(start), size(size) {}

    /** Returns the string at `offset`, or an empty one when it cannot be read. **/
    std::string at(uint32_t offset);

private:
    static constexpr uint32_t kBlockSize = 64 * 1024;

    const std::vector<char>* block(uint32_t index);

    const MemoryReader& read;
    uint64_t start;
    uint32_t size;
    std::map<uint32_t, std::vector<char>> blocks;
};

} // namespace smalldbg_internal
