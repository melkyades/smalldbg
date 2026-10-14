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
};

/** Reads the load commands of the 64-bit image loaded at `base`. Returns false
 *  when there is no such image there. **/
bool readLoadedMachO(const MemoryReader& read, uint64_t base, LoadedMachO& image);

} // namespace smalldbg_internal
