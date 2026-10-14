// POSIX platform helpers implementation
#include "../Platform.h"
#include <unistd.h>

#include <initializer_list>

namespace smalldbg_internal {
    uint64_t current_pid() {
        return static_cast<uint64_t>(::getpid());
    }

    bool isThreadStarter(const std::string& /*module*/,
                         const std::string& function) {
        for (const char* starter : {"start_thread", "clone", "__clone",
                                    "clone3", "_pthread_start", "thread_start",
                                    "_start", "__libc_start_main",
                                    "__libc_start_call_main", "start"})
            if (function == starter) return true;
        return false;
    }

#ifndef __APPLE__
    // An image loaded on macOS is read in platform/posix/macos/LoadedMachO.cpp.
    std::vector<smalldbg::ModuleSection> moduleSections(
        const MemoryReader&, uint64_t, uint64_t) {
        return {};
    }
#endif
}
