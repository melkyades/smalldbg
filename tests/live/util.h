#pragma once
#include <cstdint>
#include <cstdlib>
#include <string>

namespace smalldbg {
namespace test {

// Absolute path to the test_target executable that sits next to the test
// binary, so the live tests work regardless of ctest's working directory.
// Defined per-platform in util-win32.cpp / util-posix.cpp.
std::string defaultTestTargetPath();

// The test_target the live tests run: the one SMALLDBG_TEST_TARGET names when
// it is set, so a 32-bit build runs the same tests against a WoW64 target, and
// the one next to the test binary otherwise.
inline std::string testTargetPath() {
    if (const char* other = std::getenv("SMALLDBG_TEST_TARGET")) return other;
    return defaultTestTargetPath();
}

/** test_target started as an ordinary process in "wait" mode, for tests that
 *  attach to it. The constructor returns once the target is waiting on its
 *  stdin, with all its startup modules loaded. The target is ended when this
 *  goes away, if it has not exited by then. Windows only, like the live tests.
 **/
class WaitingTarget {
public:
    WaitingTarget();
    ~WaitingTarget();
    WaitingTarget(const WaitingTarget&) = delete;
    WaitingTarget& operator=(const WaitingTarget&) = delete;

    uintptr_t pid() const { return processId; }

    // Sends the line the target waits for, so it runs on to its exit.
    void release();

    // Returns the target's exit code, or -1 when it has not exited within
    // `timeoutMs`.
    int waitForExit(int timeoutMs);

private:
    void* process{nullptr};
    void* stdinWrite{nullptr};
    void* stdoutRead{nullptr};
    uintptr_t processId{0};
};

} // namespace test
} // namespace smalldbg
