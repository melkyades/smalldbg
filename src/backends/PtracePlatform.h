// Platform abstraction for the ptrace-based debugger backend.
// Encapsulates differences between macOS (Mach APIs) and Linux (/proc, ptrace).
#pragma once

#include "../../include/smalldbg/Types.h"
#include <functional>
#include <vector>
#include <memory>
#include <string>

namespace smalldbg {

struct Registers;
class Arch;

class PtracePlatform {
public:
    virtual ~PtracePlatform() = default;

    // Point to the backend's log callback so the platform can log
    // without needing its own callback management.
    void setLogPtr(std::function<void(const std::string&)>* ptr) { logPtr = ptr; }

    // -- ptrace wrappers --
    virtual int ptraceTraceMe() = 0;
    virtual int ptraceAttach(int pid) = 0;
    virtual int ptraceDetach(int pid) = 0;
    virtual int ptraceContinue(int pid) = 0;
    virtual int ptraceStep(int pid) = 0;
    virtual void ptraceKill(int pid) = 0;

    // Acquire platform-specific process handle (e.g. Mach task port on macOS).
    // Must be called after the target is stopped.
    virtual Status acquireProcess(int pid) = 0;

    // Release platform-specific process handle.
    virtual void releaseProcess() = 0;

    // -- Memory --
    virtual Status readMemory(Address addr, void* buf, size_t size) const = 0;
    virtual Status writeMemory(Address addr, const void* data, size_t size) = 0;

    // -- Registers --
    virtual Status getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const = 0;
    virtual Status setThreadPc(ThreadId tid, Address pc) const = 0;

    // -- Thread enumeration --
    virtual std::vector<ThreadId> enumerateThreads() = 0;

    // -- Module enumeration --
    virtual std::vector<ModuleInfo> enumerateModules() const = 0;

    // Factory: creates the platform-appropriate implementation.
    static std::unique_ptr<PtracePlatform> create();

protected:
    void doLog(const std::string& msg) const {
        if (logPtr && *logPtr) (*logPtr)(msg);
    }

    std::function<void(const std::string&)>* logPtr{nullptr};
};

} // namespace smalldbg
