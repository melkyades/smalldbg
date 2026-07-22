// End-to-end TTD test: open a recorded trace, run forward to a breakpoint, and
// step backwards.
//
// The trace is recorded (once, cached next to test_target.exe, re-recorded when
// stale) by ttd_recorder.exe — a separate requireAdministrator helper, so this
// process stays unelevated and only replays. The recorder raises a UAC prompt.
//
// SKIPs when it can't get a trace (no tttracer.exe, UAC declined, non-interactive)
// or replay is unavailable (no dbgeng — run tools/pack_windbg_dlls.sh, or set
// %SMALLDBG_DBGENG_DIR%). %SMALLDBG_TTD_TRACE% forces an explicit .run path.
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"

#include "util.h"

#include <cstdio>
#include <cstdlib>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

using namespace smalldbg;

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

// Directory holding the test binaries.
std::wstring binDir() {
    std::wstring target = widen(test::testTargetPath());
    size_t slash = target.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : target.substr(0, slash);
}

bool fileTime(const std::wstring& path, FILETIME& out) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    out = data.ftLastWriteTime;
    return true;
}

// True if `trace` is present and at least as new as test_target.exe.
bool traceIsFresh(const std::wstring& trace, const std::wstring& target) {
    FILETIME traceTime, targetTime;
    if (!fileTime(trace, traceTime)) return false;
    if (!fileTime(target, targetTime)) return true;  // no target to compare against
    return CompareFileTime(&traceTime, &targetTime) >= 0;
}

// Run ttd_recorder.exe; its manifest makes ShellExecuteEx raise the UAC prompt.
// Returns true only if it ran and exited 0 (a declined prompt returns false).
bool runRecorder(const std::wstring& recorder, const std::wstring& target,
                 const std::wstring& outRun) {
    std::wstring params = L"\"" + target + L"\" \"" + outRun + L"\"";

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.lpFile = recorder.c_str();       // default verb: manifest triggers UAC
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) return false;  // e.g. ERROR_CANCELLED

    WaitForSingleObject(sei.hProcess, 180000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return code == 0;
}

// Trace path, recording one if the cache is missing or stale. Empty = none.
std::string obtainTrace() {
    if (const char* provided = std::getenv("SMALLDBG_TTD_TRACE"))
        return provided;

    const std::wstring target = widen(test::testTargetPath());
    const std::wstring cache = binDir() + L"\\test_target.ttd.run";

    if (!traceIsFresh(cache, target)) {
        const std::wstring recorder = binDir() + L"\\ttd_recorder.exe";
        runRecorder(recorder, target, cache);  // best-effort; verified below
    }

    return traceIsFresh(cache, target) ? narrow(cache) : std::string{};
}

} // namespace

TEST_CASE("TTD trace replays and steps backwards") {
    std::string trace = obtainTrace();
    if (trace.empty()) {
        MESSAGE("SKIP: no TTD trace available (needs tttracer.exe + the elevated "
                "ttd_recorder helper, or set SMALLDBG_TTD_TRACE to a .run file)");
        return;
    }

    Debugger dbg(Mode::External, X64::instance());
    if (std::getenv("SMALLDBG_TEST_LOG"))
        dbg.setLogCallback([](const std::string& m){ fprintf(stderr, "LOG %s\n", m.c_str()); });

    Status opened = dbg.openTrace(trace);
    if (opened != Status::Ok) {
        MESSAGE("SKIP: openTrace failed — no TTD-capable dbgeng.dll installed "
                "(run tools/pack_windbg_dlls.sh, or set SMALLDBG_DBGENG_DIR), "
                "or the trace architecture does not match this host");
        return;
    }

    CHECK(dbg.isTTDTrace());
    CHECK(dbg.isAttached());

    // Run forward to break_here so we have a known position to reverse from.
    auto* symbols = dbg.getSymbolProvider();
    REQUIRE(symbols != nullptr);
    auto sym = symbols->getSymbolByName("test_target!break_here");
    REQUIRE(sym.has_value());
    REQUIRE(sym->address != 0);

    REQUIRE(dbg.setBreakpoint(sym->address, "break_here") == Status::Ok);
    REQUIRE(dbg.resume() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::Breakpoint, 30000) == StopReason::Breakpoint);

    Registers atBreak;
    REQUIRE(dbg.getRegisters(atBreak) == Status::Ok);
    const Address breakIp = atBreak.ip();
    CHECK(breakIp >= sym->address);

    // Step backwards: the instruction pointer must move off the breakpoint.
    REQUIRE(dbg.stepBack() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 30000) != StopReason::None);
    CHECK(dbg.isStopped());

    Registers afterBack;
    REQUIRE(dbg.getRegisters(afterBack) == Status::Ok);
    CHECK(afterBack.ip() != breakIp);

    dbg.detach();
}
