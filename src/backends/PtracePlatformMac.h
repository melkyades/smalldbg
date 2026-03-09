// macOS PtracePlatform — uses Mach APIs for memory, registers, and threads.
#pragma once

#include "PtracePlatform.h"
#include <mach/mach_types.h>

namespace smalldbg {

class PtracePlatformMac : public PtracePlatform {
public:
    ~PtracePlatformMac() override;

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
    mach_port_t taskPort{MACH_PORT_NULL};
    std::vector<mach_port_t> cachedThreadPorts;

    // Read one dyld_image_info entry and append to modules
    void readModuleEntry(std::vector<ModuleInfo>& modules, Address entryAddr) const;
};

} // namespace smalldbg
