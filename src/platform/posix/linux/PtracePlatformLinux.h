// Linux PtracePlatform — uses ptrace, /proc, and process_vm_readv.
#pragma once

#include "../../../backends/PtracePlatform.h"
#include "CallFrameInfo.h"

#include <deque>
#include <map>
#include <set>
#include <utility>

namespace smalldbg {

class PtracePlatformLinux : public PtracePlatform {
public:
    ~PtracePlatformLinux() override = default;

    int ptraceTraceMe() override;
    int ptraceAttach(int pid) override;
    int ptraceDetach(int pid) override;
    int ptraceContinue(int pid) override;
    int ptraceStep(int pid, ThreadId thread) override;
    void ptraceKill(int pid) override;
    int interrupt(int pid) override;
    int attachStopped(int pid) override;
    int waitForStop(int pid, int timeoutMs, int& status) override;
    ThreadId stoppedThread() const override { return lastStopped; }

    Status acquireProcess(int pid) override;
    void releaseProcess() override;

    Status readMemory(Address addr, void* buf, size_t size) const override;
    Status writeMemory(Address addr, const void* data, size_t size) override;

    Status getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const override;
    Status setThreadPc(ThreadId tid, Address pc) const override;
    Address codeAddress(Address returnAddress) const override;
    bool recoverCallerFromFrameInfo(Registers& regs, bool innermost) const override;

    std::vector<ThreadId> enumerateThreads() override;
    std::vector<ModuleInfo> enumerateModules() const override;

private:
    int targetPid{-1};

    // Every thread of the target is traced, and they stop and run together:
    // when one stops the others are halted, so that any of them can be read.
    enum class ThreadState {
        Running,
        Stopped,
        Starting,  // cloned, and its first stop not yet seen
    };
    std::map<ThreadId, ThreadState> threads;
    // Threads sent a SIGSTOP to halt them that stopped for something else
    // first; the SIGSTOP still comes, and is taken when it does.
    std::set<ThreadId> stopQueued;
    // Stops met while halting the other threads, to be reported in turn
    // before the target runs again: each with the thread and its wait status.
    std::deque<std::pair<ThreadId, int>> pendingStops;
    ThreadId lastStopped{0};
    // The bits of a code address that hold a pointer authentication
    // signature, 0 where the CPU does not sign return addresses.
    Address signatureBits{0};

    // The modules, and the call frame information of each by its load
    // address, read while the target is stopped. Libraries load and unload
    // while it runs, so both are dropped when it resumes.
    mutable std::vector<ModuleInfo> stoppedModules;
    mutable std::map<Address, std::optional<CallFrameInfo>> frameInfo;
    void forgetModules();
    ThreadId stepping{0};  // the thread single-stepping, 0 when none is

    // Answered by accept() for an event it dealt with itself
    static constexpr int kHandled = -3;

    void traceClones(ThreadId tid) const;
    void resumeThread(ThreadId tid);
    bool nextEvent(ThreadId& tid, int& status);
    int accept(ThreadId tid, int status);
    void haltOthers(ThreadId except);
    ThreadId addClone(ThreadId parent);
    void forget();

    // Write a single aligned word via PTRACE_POKEDATA
    Status pokeWord(Address wordAddr, long word) const;

    // Parse one line of /proc/<pid>/maps and append to modules if it names a
    // file with code. `imageStarts` keeps where each file's mapping at offset 0
    // starts.
    void parseMapsLine(std::vector<ModuleInfo>& modules,
                       std::map<std::string, Address>& imageStarts,
                       const std::string& line) const;
};

} // namespace smalldbg
