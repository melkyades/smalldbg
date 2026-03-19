// PtracePlatformLinux — Linux implementation using ptrace + /proc filesystem.
//
// Uses:
//   - ptrace(PTRACE_TRACEME / PTRACE_ATTACH / PTRACE_DETACH / PTRACE_CONT / PTRACE_SINGLESTEP)
//   - process_vm_readv for efficient memory reads
//   - PTRACE_PEEKDATA / PTRACE_POKEDATA for memory writes (bypasses page protections)
//   - PTRACE_GETREGS / PTRACE_SETREGS (x86_64) or PTRACE_GETREGSET (ARM64)
//   - /proc/<pid>/task/ for thread enumeration
//   - /proc/<pid>/maps for module enumeration

#include "PtracePlatformLinux.h"
#include "../../../../include/smalldbg/Arch.h"
#include <cstring>
#include <cerrno>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <sstream>

#if defined(__x86_64__)
#include <sys/user.h>  // struct user_regs_struct
#elif defined(__aarch64__)
#include <elf.h>       // NT_PRSTATUS
#include <linux/uio.h>
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

int PtracePlatformLinux::ptraceDetach(int pid) {
    return static_cast<int>(ptrace(PTRACE_DETACH, pid, nullptr, nullptr));
}

int PtracePlatformLinux::ptraceContinue(int pid) {
    long result = ptrace(PTRACE_CONT, pid, nullptr, 0);
    if (result < 0)
        doLog("(ptrace) PTRACE_CONT failed: " + std::string(strerror(errno)));
    return static_cast<int>(result);
}

int PtracePlatformLinux::ptraceStep(int pid) {
    long result = ptrace(PTRACE_SINGLESTEP, pid, nullptr, 0);
    if (result < 0)
        doLog("(ptrace) PTRACE_SINGLESTEP failed: " + std::string(strerror(errno)));
    return static_cast<int>(result);
}

void PtracePlatformLinux::ptraceKill(int pid) {
    kill(pid, SIGKILL);
}

// ---------------------------------------------------------------------------
// Process handle — no kernel resource to acquire on Linux
// ---------------------------------------------------------------------------

Status PtracePlatformLinux::acquireProcess(int pid) {
    targetPid = pid;
    return Status::Ok;
}

void PtracePlatformLinux::releaseProcess() {
    targetPid = -1;
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

void PtracePlatformLinux::parseMapsLine(std::vector<ModuleInfo>& modules,
                                         const std::string& line) const {
    // Format: addr1-addr2 perms offset dev inode [pathname]
    // Example: 7f1234000000-7f1234021000 r-xp 00000000 fd:01 12345 /usr/lib/libfoo.so
    std::istringstream iss(line);
    std::string addrRange, perms, offset, dev, inode, path;
    if (!(iss >> addrRange >> perms >> offset >> dev >> inode)) return;
    std::getline(iss >> std::ws, path);
    if (path.empty() || path[0] != '/') return;

    // Only use r-xp entries (executable mappings)
    if (perms.size() < 4 || perms[2] != 'x') return;

    // Parse load address from the range
    auto dash = addrRange.find('-');
    if (dash == std::string::npos) return;
    Address loadAddr = std::strtoull(addrRange.substr(0, dash).c_str(), nullptr, 16);

    // Avoid duplicates (same path already seen)
    for (auto& m : modules) {
        if (m.path == path) return;
    }

    ModuleInfo mod;
    mod.path = path;
    mod.loadAddress = loadAddr;
    mod.slide = 0;
    modules.push_back(std::move(mod));
}

std::vector<ModuleInfo> PtracePlatformLinux::enumerateModules() const {
    std::vector<ModuleInfo> modules;
    if (targetPid < 0) return modules;

    std::string mapsPath = "/proc/" + std::to_string(targetPid) + "/maps";
    std::ifstream ifs(mapsPath);
    if (!ifs) return modules;

    std::string line;
    while (std::getline(ifs, line)) {
        parseMapsLine(modules, line);
    }
    return modules;
}

} // namespace smalldbg
