#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/Thread.h"
#include "smalldbg/StackTrace.h"
#include <iostream>
#include <iomanip>

int main(int argc, char** argv) {
    std::string eggPath = "/Users/javierpimas/d/egg/egg-compiler/runtime/cpp/build/Darwin-arm64-Debug/egg";
    std::vector<std::string> args;

    if (argc > 1) eggPath = argv[1];
    for (int i = 2; i < argc; i++)
        args.push_back(argv[i]);

    std::cout << "Launching: " << eggPath << std::endl;
    for (auto& a : args) std::cout << "  arg: " << a << std::endl;

    smalldbg::Debugger dbg(smalldbg::Mode::External, smalldbg::ARM64::instance());

    dbg.setLogCallback([](const std::string& msg) {
        std::cerr << "[dbg] " << msg << std::endl;
    });

    auto status = dbg.launch(eggPath, args);
    if (status != smalldbg::Status::Ok) {
        std::cerr << "Failed to launch" << std::endl;
        return 1;
    }

    std::cout << "Launched, PID=" << dbg.attachedPid().value_or(0) << std::endl;
    std::cout << "Resuming and waiting for crash..." << std::endl;

    dbg.resume();

    // Wait for a stop event (crash, exception, exit)
    auto reason = dbg.waitForEvent(smalldbg::StopReason::None, 120000);
    std::cout << "Stopped, reason=" << static_cast<int>(reason) << std::endl;

    if (reason == smalldbg::StopReason::ProcessExit) {
        std::cout << "Process exited normally (no crash)." << std::endl;
        return 0;
    }

    // Get stack trace
    auto process = dbg.getProcess();
    if (!process) {
        std::cerr << "No process" << std::endl;
        return 1;
    }

    auto thread = process->primaryThread();
    if (!thread) {
        std::cerr << "No primary thread" << std::endl;
        return 1;
    }

    smalldbg::StackTrace trace(thread.get());
    auto unwindStatus = trace.unwind(256);
    if (unwindStatus != smalldbg::Status::Ok) {
        std::cerr << "unwind returned status " << static_cast<int>(unwindStatus) << std::endl;
        std::cerr << "Attempting manual frame walk from registers..." << std::endl;
    }

    const auto& frames = trace.getFrames();
    std::cout << "\n=== Stack Trace (" << frames.size() << " frames) ===" << std::endl;
    for (size_t i = 0; i < frames.size(); i++) {
        const auto& f = *frames[i];
        std::cout << "#" << std::left << std::setw(3) << i
                  << " 0x" << std::hex << f.ip() << std::dec << "  ";
        if (!f.moduleName.empty() && f.moduleName != "<unknown>")
            std::cout << f.moduleName << "!";
        if (!f.functionName.empty() && f.functionName != "<unknown>")
            std::cout << f.functionName;
        else
            std::cout << "???";
        if (f.functionOffset > 0)
            std::cout << "+0x" << std::hex << f.functionOffset << std::dec;
        if (!f.sourceFile.empty())
            std::cout << " (" << f.sourceFile << ":" << f.sourceLine << ")";
        std::cout << std::endl;
    }

    // Also dump registers
    smalldbg::Registers regs;
    if (dbg.getRegisters(regs) == smalldbg::Status::Ok) {
        std::cout << "\n=== Registers ===" << std::endl;
        std::cout << "pc=0x" << std::hex << regs.arm64.pc << std::endl;
        std::cout << "sp=0x" << regs.arm64.sp << std::endl;
        std::cout << "fp=0x" << regs.arm64.x29_fp << std::endl;
        std::cout << "lr=0x" << regs.arm64.x30_lr << std::dec << std::endl;
    }

    dbg.detach();
    return 0;
}
