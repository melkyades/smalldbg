#include "smalldbg/Debugger.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::Arch::X64);
    bool sawAttach = false;
    dbg.setLogCallback([&sawAttach](const std::string &m){
        if (m.find("attached")!=std::string::npos) sawAttach = true;
        std::cout << "[TEST LOG] " << m << std::endl;
    });

    // Launch a short-lived, instrumented debug target that the tests control.
    // We build `test_target` in-tree and run it here so tests are deterministic.
#if defined(_WIN32)
    auto s = dbg.launch("test_target.exe", {"wait"});
#else
    auto s = dbg.launch("./test_target", {"wait"});
#endif
    if (s != smalldbg::Status::Ok) return 2;
    // allow the debug loop to start for a short while
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    if (!dbg.isAttached()) return 3;

    // memory tests skipped for real backend

    // registers (try to read, but don't fail the test if unavailable)
    smalldbg::Registers r;
    if (dbg.getRegisters(r) != smalldbg::Status::Ok) return 12;
    if (r.arch != smalldbg::Arch::X64) return 13;

    if (dbg.detach() != smalldbg::Status::Ok) return 7;

    return 0;
}
