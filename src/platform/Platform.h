// Platform utility helpers (generic container for small platform-specific helpers)
#pragma once

#include <cstdint>

namespace smalldbg_internal {
    // returns the current process id as a 64-bit integer
    uint64_t current_pid();

    // (placeholders for future helpers; keep them here so we only add files below)
}
