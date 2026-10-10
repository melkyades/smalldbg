// Platform utility helpers (generic container for small platform-specific helpers)
#pragma once

#include "smalldbg/Types.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Prevents a function from being inlined into its callers. Used where code
// relies on the function having its own reachable symbol address (e.g. a
// breakpoint probe), which the compiler would otherwise fold away.
#if defined(_MSC_VER)
#define SMALLDBG_NOINLINE __declspec(noinline)
#else
#define SMALLDBG_NOINLINE __attribute__((noinline))
#endif

namespace smalldbg_internal {
    // returns the current process id as a 64-bit integer
    uint64_t current_pid();

    // Returns true for a frame the system puts at the base of every thread's
    // stack, such as the OS's and the C runtime's thread starters.
    bool isThreadStarter(const std::string& module, const std::string& function);

    // Reads `size` bytes of the target at an address. Returns false when it cannot.
    using MemoryReader = std::function<bool(uint64_t, void*, size_t)>;

    // Returns the sections the image loaded at `base` declares, clipped to
    // `end`. Returns none when its headers cannot be read or are in a format
    // this platform does not read.
    std::vector<smalldbg::ModuleSection> moduleSections(
        const MemoryReader& read, uint64_t base, uint64_t end);

    // (placeholders for future helpers; keep them here so we only add files below)
}
