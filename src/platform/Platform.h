// Platform utility helpers (generic container for small platform-specific helpers)
#pragma once

#include <cstdint>

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

    // (placeholders for future helpers; keep them here so we only add files below)
}
