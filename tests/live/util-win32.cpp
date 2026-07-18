#include "util.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace smalldbg {
namespace test {

std::string testTargetPath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string self(buf);
    size_t slash = self.find_last_of("\\/");
    std::string dir = (slash == std::string::npos) ? "." : self.substr(0, slash);
    return dir + "\\test_target.exe";
}

} // namespace test
} // namespace smalldbg
