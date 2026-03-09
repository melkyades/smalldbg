// Linux PtracePlatform — uses ptrace, /proc, and process_vm_readv.
#pragma once

#include "PtracePlatform.h"

namespace smalldbg {

class PtracePlatformLinux : public PtracePlatform {
public:
    ~PtracePlatformLinux() override = default;

    int ptraceTraceMe() override;
    int ptraceAttach(int pid) override;
    int ptraceDetach(int pid) override;
    int ptraceContinue(int pid) override;
    int ptraceStep(int pid) override;
    void ptraceKill(int pid) override;

    Status acquireProcess(int pid) override;
    void releaseProcess() override;

    Status readMemory(Address addr, void* buf, size_t size) const override;
    Status writeMemory(Address addr, const void* data, size_t size) override;

    Status getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const override;
    Status setThreadPc(ThreadId tid, Address pc) const override;

    std::vector<ThreadId> enumerateThreads() override;
    std::vector<ModuleInfo> enumerateModules() const override;

private:
    int targetPid{-1};

    // Write a single aligned word via PTRACE_POKEDATA
    Status pokeWord(Address wordAddr, long word) const;

    // Parse one line of /proc/<pid>/maps and append to modules if it names a file
    void parseMapsLine(std::vector<ModuleInfo>& modules, const std::string& line) const;
};

} // namespace smalldbg
