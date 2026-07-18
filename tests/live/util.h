#pragma once
#include <string>

namespace smalldbg {
namespace test {

// Absolute path to the test_target executable that sits next to the test
// binary, so the live tests work regardless of ctest's working directory.
// Defined per-platform in util-win32.cpp / util-posix.cpp.
std::string testTargetPath();

} // namespace test
} // namespace smalldbg
