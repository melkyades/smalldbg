#include "util.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace smalldbg {
namespace test {

std::string defaultTestTargetPath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string self(buf);
    size_t slash = self.find_last_of("\\/");
    std::string dir = (slash == std::string::npos) ? "." : self.substr(0, slash);
    return dir + "\\test_target.exe";
}

namespace {

// Reads the target's output until it says it is waiting. Returns false when
// the pipe closes first.
bool readUntilWaiting(HANDLE out) {
    std::string seen;
    char buf[256];
    DWORD got = 0;
    while (ReadFile(out, buf, sizeof(buf), &got, nullptr) && got > 0) {
        seen.append(buf, got);
        if (seen.find("waiting for debugger input") != std::string::npos)
            return true;
    }
    return false;
}

} // namespace

WaitingTarget::WaitingTarget() {
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE stdinRead = nullptr, stdoutWrite = nullptr;
    CreatePipe(&stdinRead, &stdinWrite, &inherit, 0);
    CreatePipe(&stdoutRead, &stdoutWrite, &inherit, 0);
    SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = stdinRead;
    startup.hStdOutput = stdoutWrite;
    startup.hStdError = stdoutWrite;

    std::string command = "\"" + testTargetPath() + "\" wait";
    PROCESS_INFORMATION info{};
    if (CreateProcessA(nullptr, command.data(), nullptr, nullptr, TRUE, 0,
                       nullptr, nullptr, &startup, &info)) {
        process = info.hProcess;
        processId = info.dwProcessId;
        CloseHandle(info.hThread);
    }
    CloseHandle(stdinRead);
    CloseHandle(stdoutWrite);

    if (process) readUntilWaiting(stdoutRead);
}

WaitingTarget::~WaitingTarget() {
    if (process && waitForExit(0) < 0) TerminateProcess(process, 1);
    for (void* handle : {process, stdinWrite, stdoutRead})
        if (handle) CloseHandle(handle);
}

void WaitingTarget::release() {
    DWORD written = 0;
    WriteFile(stdinWrite, "\n", 1, &written, nullptr);
}

int WaitingTarget::waitForExit(int timeoutMs) {
    if (!process || WaitForSingleObject(process, timeoutMs) != WAIT_OBJECT_0)
        return -1;
    DWORD code = 0;
    GetExitCodeProcess(process, &code);
    return static_cast<int>(code);
}

} // namespace test
} // namespace smalldbg
