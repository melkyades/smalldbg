// Standalone TTD recorder, built with a requireAdministrator manifest so the
// (unelevated) tests can elevate recording alone via one UAC prompt.
//
// Usage:  ttd_recorder.exe <target_exe> <output_run_path>
// Records <target_exe> under the inbox tttracer.exe into <output_run_path>.
// Exit 0 on success.
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

// Newest *.run file directly inside `dir`, or L"" if there is none.
std::wstring newestRunFile(const std::wstring& dir) {
    std::wstring pattern = dir + L"\\*.run";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return {};

    std::wstring best;
    FILETIME bestTime{};
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) >= 0) {
            bestTime = fd.ftLastWriteTime;
            best = dir + L"\\" + fd.cFileName;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return best;
}

void removeTree(const std::wstring& dir) {
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            DeleteFileW((dir + L"\\" + name).c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) return 2;
    const std::wstring target = argv[1];
    const std::wstring outRun = argv[2];

    // Locate the inbox tttracer.exe on PATH (System32).
    wchar_t tracer[MAX_PATH];
    if (SearchPathW(nullptr, L"tttracer.exe", nullptr, MAX_PATH, tracer, nullptr) == 0)
        return 3;

    // Record into a fresh temp dir, then move the produced trace to outRun.
    wchar_t tempPath[MAX_PATH];
    DWORD tn = GetTempPathW(MAX_PATH, tempPath);
    if (tn == 0 || tn >= MAX_PATH) return 4;
    std::wstring outDir = std::wstring(tempPath) + L"smalldbg_ttd_rec_"
                          + std::to_wstring(GetCurrentProcessId());
    if (!CreateDirectoryW(outDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return 4;

    std::wstring cmd = L"\"" + std::wstring(tracer) + L"\" -out \"" + outDir
                       + L"\" \"" + target + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        removeTree(outDir);
        return 5;
    }
    WaitForSingleObject(pi.hProcess, 120000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::wstring run = newestRunFile(outDir);
    int rc = 0;
    if (run.empty()) {
        rc = 6;  // tttracer produced no trace
    } else {
        DeleteFileW(outRun.c_str());
        if (!MoveFileW(run.c_str(), outRun.c_str()))
            rc = CopyFileW(run.c_str(), outRun.c_str(), FALSE) ? 0 : 7;
    }
    removeTree(outDir);
    return rc;
}
