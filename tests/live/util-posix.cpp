#include "util.h"

#include <climits>
#include <cstdint>

#if defined(__APPLE__)
#  include <mach-o/dyld.h>
#else
#  include <unistd.h>
#endif

namespace smalldbg {
namespace test {

std::string testTargetPath() {
    std::string self;
#if defined(__APPLE__)
    char buf[PATH_MAX] = {};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) self = buf;
#else
    char buf[PATH_MAX] = {};
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; self = buf; }
#endif
    size_t slash = self.find_last_of('/');
    std::string dir = (slash == std::string::npos) ? "." : self.substr(0, slash);
    return dir + "/test_target";
}

} // namespace test
} // namespace smalldbg
