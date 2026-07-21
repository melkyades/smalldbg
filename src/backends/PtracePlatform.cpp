// Default spawnStopped(): fork + PT_TRACE_ME + execvp, parent waits for the
// SIGTRAP-at-exec. Platforms where this doesn't hold override it.

#include "PtracePlatform.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

namespace smalldbg {

int PtracePlatform::spawnStopped(const std::string& path,
                                 const std::vector<std::string>& args) {
    pid_t child = fork();
    if (child < 0) {
        doLog(std::string("(ptrace) fork failed: ") + strerror(errno));
        return -1;
    }

    if (child == 0) {
        // --- child process ---
        if (ptraceTraceMe() < 0) {
            // We're already past fork; can't use doLog (parent-side closure).
            fprintf(stderr, "(ptrace) PT_TRACE_ME failed in child: %s\n",
                    strerror(errno));
            fflush(stderr);
            _exit(126);
        }

        std::vector<const char*> argv;
        argv.push_back(path.c_str());
        for (auto& a : args) argv.push_back(a.c_str());
        argv.push_back(nullptr);

        execvp(path.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    // --- parent process ---
    int status = 0;
    pid_t r = waitpid(child, &status, 0);
    if (r < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "(ptrace) waitpid failed: %s (errno=%d)",
                 strerror(errno), errno);
        doLog(buf);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        char buf[256];
        if (WIFEXITED(status)) {
            snprintf(buf, sizeof(buf),
                "(ptrace) child exited with status %d (raw=0x%x) — likely execvp failed",
                WEXITSTATUS(status), status);
        } else if (WIFSIGNALED(status)) {
            snprintf(buf, sizeof(buf),
                "(ptrace) child killed by signal %d (%s)",
                WTERMSIG(status), strsignal(WTERMSIG(status)));
        } else {
            snprintf(buf, sizeof(buf),
                "(ptrace) child did not stop: raw status=0x%x", status);
        }
        doLog(buf);
        return -1;
    }

    return static_cast<int>(child);
}

} // namespace smalldbg
