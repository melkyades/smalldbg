// POSIX platform helpers implementation
#include "platform/Platform.h"
#include <unistd.h>

namespace smalldbg_internal {
    uint64_t current_pid() {
        return static_cast<uint64_t>(::getpid());
    }
}
