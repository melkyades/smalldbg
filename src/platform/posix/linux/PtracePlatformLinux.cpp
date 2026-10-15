// PtracePlatformLinux — Linux implementation using ptrace + /proc filesystem.
//
// Uses:
//   - ptrace(PTRACE_TRACEME / PTRACE_ATTACH / PTRACE_DETACH / PTRACE_CONT / PTRACE_SINGLESTEP)
//   - process_vm_readv for efficient memory reads
//   - PTRACE_PEEKDATA / PTRACE_POKEDATA for memory writes (bypasses page protections)
//   - PTRACE_GETREGS / PTRACE_SETREGS (x86_64) or PTRACE_GETREGSET (ARM64)
//   - /proc/<pid>/task/ for thread enumeration
//   - /proc/<pid>/maps for module enumeration
//
// Every thread is traced: those there when attaching, and through
// PTRACE_O_TRACECLONE each one the target starts. They stop together, as a
// debugger's user expects: when one stops the others are sent SIGSTOP and
// waited for, and continuing resumes them all.

#include "PtracePlatformLinux.h"
#include "../../../../include/smalldbg/Arch.h"
#include <cstring>
#include <cerrno>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <chrono>
#include <fstream>
#include <sstream>
#include <vector>

#if defined(__x86_64__)
#include <sys/user.h>  // struct user_regs_struct
#elif defined(__aarch64__)
#include <elf.h>       // NT_PRSTATUS; struct iovec comes from <sys/uio.h>
#endif

namespace smalldbg {

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<PtracePlatform> PtracePlatform::create() {
    return std::make_unique<PtracePlatformLinux>();
}

// ---------------------------------------------------------------------------
// ptrace wrappers
// ---------------------------------------------------------------------------

int PtracePlatformLinux::ptraceTraceMe() {
    return static_cast<int>(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr));
}

int PtracePlatformLinux::ptraceAttach(int pid) {
    long result = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    if (result < 0)
        doLog("(ptrace) PTRACE_ATTACH failed: " + std::string(strerror(errno)));
    return static_cast<int>(result);
}

// A thread is detached only while stopped, and only once any SIGSTOP of ours
// has reached it: one left queued would stop the target with nobody there to
// continue it.
int PtracePlatformLinux::ptraceDetach(int pid) {
    if (threads.empty())
        return static_cast<int>(ptrace(PTRACE_DETACH, pid, nullptr, nullptr));

    haltOthers(0);
    for (ThreadId tid : stopQueued) {
        if (ptrace(PTRACE_CONT, static_cast<pid_t>(tid), nullptr, 0) < 0) continue;
        int status = 0;
        waitpid(static_cast<pid_t>(tid), &status, __WALL);
    }
    stopQueued.clear();

    int result = 0;
    for (const auto& [tid, state] : threads)
        if (ptrace(PTRACE_DETACH, static_cast<pid_t>(tid), nullptr, nullptr) < 0
            && tid == static_cast<ThreadId>(pid))
            result = -1;
    forget();
    return result;
}

// A stop met while halting the threads is still to be reported, so the target
// is left as it is: the next wait answers that stop at once, as if the target
// had run into it.
int PtracePlatformLinux::ptraceContinue(int pid) {
    if (!pendingStops.empty()) return 0;

    int result = -1;
    for (auto& [tid, state] : threads) {
        if (state != ThreadState::Stopped) continue;
        if (ptrace(PTRACE_CONT, static_cast<pid_t>(tid), nullptr, 0) < 0) {
            doLog("(ptrace) PTRACE_CONT failed for tid " + std::to_string(tid) + ": "
                  + strerror(errno));
            continue;
        }
        state = ThreadState::Running;
        result = 0;
    }
    if (threads.empty()) result = static_cast<int>(ptrace(PTRACE_CONT, pid, nullptr, 0));
    return result;
}

// Only `thread` runs; the others stay stopped.
int PtracePlatformLinux::ptraceStep(int pid, ThreadId thread) {
    ThreadId tid = thread != 0 ? thread : static_cast<ThreadId>(pid);
    long result = ptrace(PTRACE_SINGLESTEP, static_cast<pid_t>(tid), nullptr, 0);
    if (result < 0) {
        doLog("(ptrace) PTRACE_SINGLESTEP failed: " + std::string(strerror(errno)));
        return static_cast<int>(result);
    }
    stepping = tid;
    auto known = threads.find(tid);
    if (known != threads.end()) known->second = ThreadState::Running;
    return 0;
}

void PtracePlatformLinux::ptraceKill(int pid) {
    kill(pid, SIGKILL);
}

// The thread the process started on is the one stopped.
int PtracePlatformLinux::interrupt(int pid) {
    ThreadId target = 0;
    for (const auto& [tid, state] : threads)
        if (state == ThreadState::Running && (target == 0 || tid == static_cast<ThreadId>(pid)))
            target = tid;
    if (target == 0) return threads.empty() ? kill(pid, SIGSTOP) : -1;
    return static_cast<int>(syscall(SYS_tgkill, pid, static_cast<pid_t>(target), SIGSTOP));
}

// Attaches every thread the process has, looking again until no new one has
// appeared, since a running process may start threads meanwhile.
int PtracePlatformLinux::attachStopped(int pid) {
    forget();
    targetPid = pid;
    for (bool found = true; found;) {
        found = false;
        for (ThreadId tid : enumerateThreads()) {
            if (threads.count(tid)) continue;
            if (ptrace(PTRACE_ATTACH, static_cast<pid_t>(tid), nullptr, nullptr) < 0) {
                if (tid != static_cast<ThreadId>(pid)) continue;  // it has just ended
                doLog("(ptrace) PTRACE_ATTACH failed: " + std::string(strerror(errno)));
                ptraceDetach(pid);
                return -1;
            }
            int status = 0;
            if (waitpid(static_cast<pid_t>(tid), &status, __WALL) < 0 || !WIFSTOPPED(status)) {
                continue;
            }
            threads[tid] = ThreadState::Stopped;
            if (WSTOPSIG(status) != SIGSTOP) {
                stopQueued.insert(tid);
                pendingStops.emplace_back(tid, status);
            }
            found = true;
        }
    }
    if (!threads.count(static_cast<ThreadId>(pid))) {
        doLog("(ptrace) child did not stop after attach");
        ptraceDetach(pid);
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Stops — waited for thread by thread
// ---------------------------------------------------------------------------

void PtracePlatformLinux::traceClones(ThreadId tid) const {
    if (ptrace(PTRACE_SETOPTIONS, static_cast<pid_t>(tid), nullptr,
               reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0)
        doLog("(ptrace) PTRACE_SETOPTIONS failed: " + std::string(strerror(errno)));
}

void PtracePlatformLinux::resumeThread(ThreadId tid) {
    int request = tid == stepping ? PTRACE_SINGLESTEP : PTRACE_CONT;
    if (ptrace(static_cast<__ptrace_request>(request), static_cast<pid_t>(tid),
               nullptr, 0) < 0)
        return;
    threads[tid] = ThreadState::Running;
}

// Waits only on the target's own threads, each by its id: this process may be
// debugging other targets, whose stops are not this one's to take.
bool PtracePlatformLinux::nextEvent(ThreadId& tid, int& status) {
    std::vector<ThreadId> known;
    for (const auto& [id, state] : threads)
        if (state != ThreadState::Stopped) known.push_back(id);
    for (ThreadId id : known) {
        pid_t r = waitpid(static_cast<pid_t>(id), &status, WNOHANG | __WALL);
        if (r > 0) { tid = id; return true; }
        if (r < 0 && errno == ECHILD) {
            threads.erase(id);
            stopQueued.erase(id);
        }
    }
    return false;
}

// Returns a new thread's id, taken from the clone event its parent stopped on.
ThreadId PtracePlatformLinux::addClone(ThreadId parent) {
    unsigned long child = 0;
    ptrace(PTRACE_GETEVENTMSG, static_cast<pid_t>(parent), nullptr, &child);
    ThreadId tid = static_cast<ThreadId>(child);
    if (tid != 0 && !threads.count(tid)) threads[tid] = ThreadState::Starting;
    return tid;
}

// Returns the signal that stopped `tid`, -2 when the process is gone, or
// kHandled for an event that is not a stop to report: a thread starting or
// ending, or a SIGSTOP of ours arriving late.
int PtracePlatformLinux::accept(ThreadId tid, int status) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        threads.erase(tid);
        stopQueued.erase(tid);
        // The thread the process started on is reported last, when the
        // whole process has ended.
        return tid == static_cast<ThreadId>(targetPid) ? -2 : kHandled;
    }
    if (!WIFSTOPPED(status)) return kHandled;

    int sig = WSTOPSIG(status);
    if (sig == SIGTRAP && (status >> 16) == PTRACE_EVENT_CLONE) {
        addClone(tid);
        resumeThread(tid);
        return kHandled;
    }
    if (sig == SIGSTOP && threads[tid] == ThreadState::Starting) {
        resumeThread(tid);
        return kHandled;
    }
    if (sig == SIGSTOP && stopQueued.erase(tid)) {
        resumeThread(tid);
        return kHandled;
    }
    threads[tid] = ThreadState::Stopped;
    return sig;
}

// Stops every thread but `except` and waits until each has. One that stops
// for something else first keeps that stop for a later report.
void PtracePlatformLinux::haltOthers(ThreadId except) {
    std::vector<ThreadId> waiting;
    for (const auto& [tid, state] : threads) {
        if (tid == except || state == ThreadState::Stopped) continue;
        if (state == ThreadState::Running) {
            syscall(SYS_tgkill, targetPid, static_cast<pid_t>(tid), SIGSTOP);
            stopQueued.insert(tid);
        }
        waiting.push_back(tid);
    }

    for (size_t i = 0; i < waiting.size(); i++) {
        ThreadId tid = waiting[i];
        int status = 0;
        if (waitpid(static_cast<pid_t>(tid), &status, __WALL) < 0
            || WIFEXITED(status) || WIFSIGNALED(status)) {
            threads.erase(tid);
            stopQueued.erase(tid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP && (status >> 16) == PTRACE_EVENT_CLONE) {
            ThreadId child = addClone(tid);
            if (child != 0 && threads[child] == ThreadState::Starting)
                waiting.push_back(child);
        } else if (sig == SIGSTOP) {
            stopQueued.erase(tid);
        } else {
            pendingStops.emplace_back(tid, status);
        }
        threads[tid] = ThreadState::Stopped;
    }
}

int PtracePlatformLinux::waitForStop(int pid, int timeoutMs, int& status) {
    (void)pid;
    if (stepping == 0 && !pendingStops.empty()) {
        auto [tid, pending] = pendingStops.front();
        pendingStops.pop_front();
        lastStopped = tid;
        status = pending;
        return WSTOPSIG(pending);
    }

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeoutMs);
    while (true) {
        ThreadId tid = 0;
        int event = 0;
        while (nextEvent(tid, event)) {
            int sig = accept(tid, event);
            if (sig == kHandled) continue;
            status = event;
            if (sig == -2) return -2;
            stepping = 0;
            lastStopped = tid;
            haltOthers(tid);
            return sig;
        }
        if (threads.empty()) return -2;
        if (timeoutMs == 0
            || (timeoutMs > 0 && std::chrono::steady_clock::now() >= deadline))
            return -1;
        usleep(1000);
    }
}

// ---------------------------------------------------------------------------
// Pointer authentication
// ---------------------------------------------------------------------------

// The kernel says which bits of a code address hold the signature. A kernel or
// CPU without pointer authentication has no such register set.
static Address readSignatureBits(ThreadId tid) {
#if defined(__aarch64__)
    struct {
        uint64_t dataMask;
        uint64_t codeMask;
    } masks{};
    struct iovec iov = { &masks, sizeof(masks) };
    if (ptrace(PTRACE_GETREGSET, static_cast<pid_t>(tid),
               reinterpret_cast<void*>(NT_ARM_PAC_MASK), &iov) < 0)
        return 0;
    return masks.codeMask;
#else
    (void)tid;
    return 0;
#endif
}

Address PtracePlatformLinux::codeAddress(Address returnAddress) const {
    return returnAddress & ~signatureBits;
}

// ---------------------------------------------------------------------------
// Process handle — no kernel resource to acquire on Linux
// ---------------------------------------------------------------------------

// The target is stopped here, launched or attached: from now on its threads
// report the threads they start.
Status PtracePlatformLinux::acquireProcess(int pid) {
    targetPid = pid;
    if (threads.empty()) threads[static_cast<ThreadId>(pid)] = ThreadState::Stopped;
    for (const auto& [tid, state] : threads) traceClones(tid);
    lastStopped = static_cast<ThreadId>(pid);
    signatureBits = readSignatureBits(static_cast<ThreadId>(pid));
    return Status::Ok;
}

void PtracePlatformLinux::releaseProcess() {
    forget();
}

void PtracePlatformLinux::forget() {
    targetPid = -1;
    threads.clear();
    stopQueued.clear();
    pendingStops.clear();
    lastStopped = 0;
    stepping = 0;
    signatureBits = 0;
}

// ---------------------------------------------------------------------------
// Memory access
// ---------------------------------------------------------------------------

Status PtracePlatformLinux::readMemory(Address addr, void* buf, size_t size) const {
    if (targetPid < 0) return Status::NotAttached;

    struct iovec local  = { buf, size };
    struct iovec remote = { reinterpret_cast<void*>(static_cast<uintptr_t>(addr)), size };
    ssize_t n = process_vm_readv(targetPid, &local, 1, &remote, 1, 0);
    if (n != static_cast<ssize_t>(size)) return Status::Error;
    return Status::Ok;
}

Status PtracePlatformLinux::pokeWord(Address wordAddr, long word) const {
    if (ptrace(PTRACE_POKEDATA, targetPid,
               reinterpret_cast<void*>(static_cast<uintptr_t>(wordAddr)),
               reinterpret_cast<void*>(word)) < 0)
        return Status::Error;
    return Status::Ok;
}

Status PtracePlatformLinux::writeMemory(Address addr, const void* data, size_t size) {
    if (targetPid < 0) return Status::NotAttached;

    const uint8_t* src = static_cast<const uint8_t*>(data);
    constexpr size_t wordSize = sizeof(long);
    Address pos = addr;
    size_t remaining = size;

    while (remaining > 0) {
        Address wordAddr = pos & ~(wordSize - 1);
        size_t offset = static_cast<size_t>(pos - wordAddr);
        size_t toCopy = std::min(remaining, wordSize - offset);

        long word = 0;
        if (toCopy < wordSize) {
            // Partial word: read existing, merge, write back
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, targetPid,
                          reinterpret_cast<void*>(static_cast<uintptr_t>(wordAddr)),
                          nullptr);
            if (errno != 0) return Status::Error;
        }

        std::memcpy(reinterpret_cast<uint8_t*>(&word) + offset, src, toCopy);
        if (pokeWord(wordAddr, word) != Status::Ok) return Status::Error;

        src += toCopy;
        pos += toCopy;
        remaining -= toCopy;
    }
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Register access
// ---------------------------------------------------------------------------

#if defined(__x86_64__)

Status PtracePlatformLinux::getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const {
    struct user_regs_struct regs{};
    long r = ptrace(PTRACE_GETREGS, static_cast<pid_t>(tid), nullptr, &regs);
    if (r < 0) return Status::Error;

    out.arch = X64::instance();
    auto& x = out.x64;
    x.rax = regs.rax; x.rbx = regs.rbx; x.rcx = regs.rcx; x.rdx = regs.rdx;
    x.rsi = regs.rsi; x.rdi = regs.rdi; x.rbp = regs.rbp; x.rsp = regs.rsp;
    x.r8  = regs.r8;  x.r9  = regs.r9;  x.r10 = regs.r10; x.r11 = regs.r11;
    x.r12 = regs.r12; x.r13 = regs.r13; x.r14 = regs.r14; x.r15 = regs.r15;
    x.rip    = regs.rip;
    x.rflags = regs.eflags;
    x.cs = static_cast<uint16_t>(regs.cs);
    x.fs = static_cast<uint16_t>(regs.fs);
    x.gs = static_cast<uint16_t>(regs.gs);
    x.pc = regs.rip;
    x.sp = regs.rsp;

    (void)arch;
    return Status::Ok;
}

Status PtracePlatformLinux::setThreadPc(ThreadId tid, Address pc) const {
    struct user_regs_struct regs{};
    long r = ptrace(PTRACE_GETREGS, static_cast<pid_t>(tid), nullptr, &regs);
    if (r < 0) return Status::Error;

    regs.rip = pc;
    r = ptrace(PTRACE_SETREGS, static_cast<pid_t>(tid), nullptr, &regs);
    return (r == 0) ? Status::Ok : Status::Error;
}

#elif defined(__aarch64__)

Status PtracePlatformLinux::getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const {
    struct user_regs_struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } regs{};

    struct iovec iov = { &regs, sizeof(regs) };
    long r = ptrace(PTRACE_GETREGSET, static_cast<pid_t>(tid),
                    reinterpret_cast<void*>(NT_PRSTATUS), &iov);
    if (r < 0) return Status::Error;

    out.arch = ARM64::instance();
    auto& a = out.arm64;
    a.x0  = regs.regs[0];  a.x1  = regs.regs[1];  a.x2  = regs.regs[2];
    a.x3  = regs.regs[3];  a.x4  = regs.regs[4];  a.x5  = regs.regs[5];
    a.x6  = regs.regs[6];  a.x7  = regs.regs[7];  a.x8  = regs.regs[8];
    a.x9  = regs.regs[9];  a.x10 = regs.regs[10]; a.x11 = regs.regs[11];
    a.x12 = regs.regs[12]; a.x13 = regs.regs[13]; a.x14 = regs.regs[14];
    a.x15 = regs.regs[15]; a.x16 = regs.regs[16]; a.x17 = regs.regs[17];
    a.x18 = regs.regs[18]; a.x19 = regs.regs[19]; a.x20 = regs.regs[20];
    a.x21 = regs.regs[21]; a.x22 = regs.regs[22]; a.x23 = regs.regs[23];
    a.x24 = regs.regs[24]; a.x25 = regs.regs[25]; a.x26 = regs.regs[26];
    a.x27 = regs.regs[27]; a.x28 = regs.regs[28];
    a.x29_fp = regs.regs[29];
    a.x30_lr = regs.regs[30];
    a.sp = regs.sp;
    a.pc = regs.pc;

    (void)arch;
    return Status::Ok;
}

Status PtracePlatformLinux::setThreadPc(ThreadId tid, Address pc) const {
    struct user_regs_struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } regs{};

    struct iovec iov = { &regs, sizeof(regs) };
    long r = ptrace(PTRACE_GETREGSET, static_cast<pid_t>(tid),
                    reinterpret_cast<void*>(NT_PRSTATUS), &iov);
    if (r < 0) return Status::Error;

    regs.pc = pc;
    iov.iov_len = sizeof(regs);
    r = ptrace(PTRACE_SETREGSET, static_cast<pid_t>(tid),
               reinterpret_cast<void*>(NT_PRSTATUS), &iov);
    return (r == 0) ? Status::Ok : Status::Error;
}

#else
#error "Unsupported Linux architecture — add register definitions here"
#endif

// ---------------------------------------------------------------------------
// Thread enumeration (/proc/<pid>/task/)
// ---------------------------------------------------------------------------

std::vector<ThreadId> PtracePlatformLinux::enumerateThreads() {
    std::vector<ThreadId> result;
    if (targetPid < 0) return result;

    std::string taskDir = "/proc/" + std::to_string(targetPid) + "/task";
    DIR* dir = opendir(taskDir.c_str());
    if (!dir) return result;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        char* end = nullptr;
        long tid = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && tid > 0)
            result.push_back(static_cast<ThreadId>(tid));
    }
    closedir(dir);
    return result;
}

// ---------------------------------------------------------------------------
// Module enumeration (/proc/<pid>/maps)
// ---------------------------------------------------------------------------

// A module is loaded where its file's first mapping starts, the one at file
// offset 0: that is where the ELF header and the first segment are. The code
// is often in a later mapping. On x86-64, for example, the linker puts it in
// a segment of its own, so it starts a page or more after the image.
void PtracePlatformLinux::parseMapsLine(std::vector<ModuleInfo>& modules,
                                         std::map<std::string, Address>& imageStarts,
                                         const std::string& line) const {
    // Format: addr1-addr2 perms offset dev inode [pathname]
    // Example: 7f1234000000-7f1234021000 r-xp 00000000 fd:01 12345 /usr/lib/libfoo.so
    std::istringstream iss(line);
    std::string addrRange, perms, offset, dev, inode, path;
    if (!(iss >> addrRange >> perms >> offset >> dev >> inode)) return;
    std::getline(iss >> std::ws, path);
    if (path.empty() || path[0] != '/') return;

    auto dash = addrRange.find('-');
    if (dash == std::string::npos) return;
    Address start = std::strtoull(addrRange.substr(0, dash).c_str(), nullptr, 16);
    Address fileOffset = std::strtoull(offset.c_str(), nullptr, 16);
    if (fileOffset == 0 && !imageStarts.count(path)) imageStarts[path] = start;

    // Only files with code are modules
    if (perms.size() < 4 || perms[2] != 'x') return;

    // Avoid duplicates (same path already seen)
    for (auto& m : modules) {
        if (m.path == path) return;
    }

    ModuleInfo mod;
    mod.path = path;
    auto image = imageStarts.find(path);
    mod.loadAddress = image != imageStarts.end() ? image->second : start - fileOffset;
    mod.slide = 0;
    modules.push_back(std::move(mod));
}

std::vector<ModuleInfo> PtracePlatformLinux::enumerateModules() const {
    std::vector<ModuleInfo> modules;
    if (targetPid < 0) return modules;

    std::string mapsPath = "/proc/" + std::to_string(targetPid) + "/maps";
    std::ifstream ifs(mapsPath);
    if (!ifs) return modules;

    std::map<std::string, Address> imageStarts;
    std::string line;
    while (std::getline(ifs, line)) {
        parseMapsLine(modules, imageStarts, line);
    }
    return modules;
}

} // namespace smalldbg
