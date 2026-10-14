// PtracePlatformMac — macOS implementation using ptrace + Mach APIs.
//
// Uses:
//   - ptrace(PT_TRACE_ME / PT_ATTACHEXC / PT_DETACH / PT_CONTINUE / PT_STEP)
//   - Mach VM APIs for memory access  (mach_vm_read_overwrite / mach_vm_write)
//   - Mach thread APIs for registers  (thread_get_state / thread_set_state)
//   - task_threads() for thread enumeration
//   - task_info(TASK_DYLD_INFO) for module enumeration

#include "PtracePlatformMac.h"
#include "../../../../include/smalldbg/Arch.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>
#include <crt_externs.h>  // for _NSGetEnviron on macOS
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/exception_types.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <libproc.h>
#include <algorithm>
#include <chrono>
#include <optional>

namespace smalldbg {

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<PtracePlatform> PtracePlatform::create() {
    return std::make_unique<PtracePlatformMac>();
}

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------

PtracePlatformMac::~PtracePlatformMac() {
    releaseProcess();
}

// ---------------------------------------------------------------------------
// ptrace wrappers
// ---------------------------------------------------------------------------

int PtracePlatformMac::ptraceTraceMe() {
    int r = ptrace(PT_TRACE_ME, 0, nullptr, 0);
    if (r < 0) {
        // We're in the child — log() callback isn't useful (it's a parent-side
        // closure). Write directly to stderr so the user sees the real reason.
        fprintf(stderr, "(ptrace) PT_TRACE_ME failed in child: %s (errno=%d)\n",
                strerror(errno), errno);
        fflush(stderr);
    }
    return r;
}

// ---------------------------------------------------------------------------
// spawnStopped — macOS-specific launch using posix_spawn + PT_ATTACHEXC.
// ---------------------------------------------------------------------------
//
// macOS does NOT deliver a posix SIGTRAP to a PT_TRACE_ME-tracing parent after
// the child's exec — the kernel routes exec stops through Mach exceptions.
// The standard pattern (used by LLDB) is:
//   1. posix_spawn with POSIX_SPAWN_START_SUSPENDED:
//        the kernel forks, execs the new image, then sends the child SIGSTOP
//        before any user code runs.  The parent gets back the child pid.
//   2. waitpid for the SIGSTOP — confirms the child is at the entry of the
//      new image and suspended.
//   3. PT_ATTACHEXC on the child — installs Mach exception ports through
//      ptrace, so subsequent stops (breakpoints, crashes, signals) deliver
//      via waitpid as on Linux.
// At return the child is still SIGSTOP'd and ready for inspection; the caller
// resumes it later via ptraceContinue().
int PtracePlatformMac::spawnStopped(const std::string& path,
                                    const std::vector<std::string>& args,
                                    const std::string& workingDir) {
    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) != 0) {
        doLog(std::string("(ptrace) posix_spawnattr_init failed: ") + strerror(errno));
        return -1;
    }
    if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED) != 0) {
        doLog(std::string("(ptrace) posix_spawnattr_setflags failed: ") + strerror(errno));
        posix_spawnattr_destroy(&attr);
        return -1;
    }

    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(path.c_str()));
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (!workingDir.empty())
        posix_spawn_file_actions_addchdir_np(&actions, workingDir.c_str());

    pid_t child = -1;
    int spawn_rc = posix_spawn(&child, path.c_str(), &actions, &attr,
                               argv.data(), *_NSGetEnviron());
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    if (spawn_rc != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "(ptrace) posix_spawn(%s) failed: %s",
                 path.c_str(), strerror(spawn_rc));
        doLog(buf);
        return -1;
    }

    // Confirm the child is actually stopped on its SIGSTOP from the suspended
    // spawn. Using WNOHANG/WUNTRACED to be defensive against stale state.
    int status = 0;
    pid_t r = waitpid(child, &status, WUNTRACED);
    if (r < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "(ptrace) waitpid after posix_spawn failed: %s",
                 strerror(errno));
        doLog(buf);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        char buf[256];
        if (WIFEXITED(status)) {
            snprintf(buf, sizeof(buf),
                "(ptrace) child exited immediately with status %d",
                WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            snprintf(buf, sizeof(buf),
                "(ptrace) child killed by signal %d (%s) before stop",
                WTERMSIG(status), strsignal(WTERMSIG(status)));
        } else {
            snprintf(buf, sizeof(buf),
                "(ptrace) child not stopped after POSIX_SPAWN_START_SUSPENDED: status=0x%x",
                status);
        }
        doLog(buf);
        return -1;
    }

    // The exception server takes the child's ports before ptrace attaches, so
    // the first stop, the SIGSTOP of the suspended spawn, is held there too.
    bool attachedStopped = acquireProcess(child) == Status::Ok
        && ptraceAttach(child) == 0
        && ptrace(PT_CONTINUE, child, reinterpret_cast<caddr_t>(1), 0) == 0
        && waitForStop(child, 5000, status) == SIGSTOP;
    if (!attachedStopped) {
        doLog("(ptrace) " + path + " did not stop at its entry");
        releaseProcess();
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return -1;
    }
    return static_cast<int>(child);
}

int PtracePlatformMac::ptraceAttach(int pid) {
    int result = ptrace(PT_ATTACHEXC, pid, nullptr, 0);
    if (result < 0)
        doLog("(ptrace) PT_ATTACHEXC failed: " + std::string(strerror(errno)));
    return result;
}

int PtracePlatformMac::ptraceDetach(int pid) {
    return ptrace(PT_DETACH, pid, nullptr, 0);
}

int PtracePlatformMac::ptraceContinue(int pid) {
    (void)pid;  // the target is resumed by answering what stopped it
    resumeHeld();
    return 0;
}

// Hardware single-step is only used by the ARM64 watchpoints for now.
#if defined(__arm64__) || defined(__aarch64__)
namespace {

// Makes `thread` trap after its next instruction, or stop doing so.
kern_return_t setSingleStep(mach_port_t thread, bool on) {
    arm_debug_state64_t state{};
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        reinterpret_cast<thread_state_t>(&state), &count);
    if (kr != KERN_SUCCESS) return kr;
    if (on) state.__mdscr_el1 |= 1;  // MDSCR_EL1.SS
    else state.__mdscr_el1 &= ~uint64_t(1);
    return thread_set_state(thread, ARM_DEBUG_STATE64,
                            reinterpret_cast<thread_state_t>(&state), count);
}

} // namespace
#endif

int PtracePlatformMac::ptraceStep(int pid, ThreadId thread) {
    (void)thread;  // steps the process, as it always has
    int result = ptrace(PT_STEP, pid, reinterpret_cast<caddr_t>(1), 0);
    if (result < 0)
        doLog("(ptrace) PT_STEP failed: " + std::string(strerror(errno)));
    return result;
}

void PtracePlatformMac::ptraceKill(int pid) {
    ptrace(PT_KILL, pid, nullptr, 0);
}

// ---------------------------------------------------------------------------
// Process handle (Mach task port)
// ---------------------------------------------------------------------------

Status PtracePlatformMac::acquireProcess(int pid) {
    if (taskPort != MACH_PORT_NULL && targetPid == pid) return Status::Ok;
    targetPid = pid;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &taskPort);
    if (kr != KERN_SUCCESS) {
        doLog("(ptrace) task_for_pid failed: " + std::string(mach_error_string(kr))
              + " (requires sudo or com.apple.security.cs.debugger entitlement)");
        return Status::Error;
    }
    // Every stop of the target reaches the debugger through the exception
    // server, so there is no debugging it without one.
    if (startExceptionServer() != Status::Ok) {
        mach_port_deallocate(mach_task_self(), taskPort);
        taskPort = MACH_PORT_NULL;
        return Status::Error;
    }

    // Optional HW watchpoint seeded from the environment. Useful when chasing
    // "which code path wrote this stale pointer" bugs: set SMALLDBG_WATCH_ADDR
    // to the slot address (8-byte aligned) and the child traps to the Mach
    // exception server the first time it writes to it. We install the
    // watchpoint on every existing thread; newly-spawned threads would need
    // additional plumbing (fine for mostly-single-threaded targets). The same
    // values can be set at runtime via setWatchpoint().
    if (const char* wp = std::getenv("SMALLDBG_WATCH_ADDR"))
        watchAddrLive_ = std::strtoull(wp, nullptr, 0);
    if (const char* wm = std::getenv("SMALLDBG_WATCH_MATCH"))
        watchMatchLive_ = std::strtoull(wm, nullptr, 0);
    if (const char* mk = std::getenv("SMALLDBG_WATCH_MASK"))
        watchMaskLive_ = std::strtoull(mk, nullptr, 0);
    if (watchAddrLive_ != 0)
        installWatchpointAllThreads(watchAddrLive_);
    return Status::Ok;
}

void PtracePlatformMac::releaseProcess() {
    resumeHeld();
    stopExceptionServer();
    lastStopThread = 0;

    for (auto port : cachedThreadPorts)
        mach_port_deallocate(mach_task_self(), port);
    cachedThreadPorts.clear();

    if (taskPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), taskPort);
        taskPort = MACH_PORT_NULL;
    }
    targetPid = -1;
}

// ---------------------------------------------------------------------------
// Memory access (Mach VM)
// ---------------------------------------------------------------------------

Status PtracePlatformMac::readMemory(Address addr, void* buf, size_t size) const {
    if (taskPort == MACH_PORT_NULL) return Status::NotAttached;

    mach_vm_size_t outSize = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        taskPort,
        static_cast<mach_vm_address_t>(addr),
        static_cast<mach_vm_size_t>(size),
        reinterpret_cast<mach_vm_address_t>(buf),
        &outSize);

    if (kr != KERN_SUCCESS || outSize != size) return Status::Error;
    return Status::Ok;
}

namespace {

// The protection of the region holding `addr`, or nothing when no region
// holds it.
std::optional<vm_prot_t> protectionAt(mach_port_t task, Address addr) {
    mach_vm_address_t start = addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(task, &start, &size, VM_REGION_BASIC_INFO_64,
                                      reinterpret_cast<vm_region_info_t>(&info),
                                      &count, &object);
    if (kr != KERN_SUCCESS || start > addr) return std::nullopt;
    return info.protection;
}

} // namespace

namespace {

// The entry at or after `address`, or nothing past the last one.
std::optional<MapEntry> mapEntryFrom(mach_port_t task, mach_vm_address_t address) {
    MapEntry entry;
    entry.start = address;
    mach_vm_size_t size = 0;
    vm_region_extended_info_data_t info{};
    mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
    mach_port_t object = MACH_PORT_NULL;
    if (mach_vm_region(task, &entry.start, &size, VM_REGION_EXTENDED_INFO,
                       reinterpret_cast<vm_region_info_t>(&info), &count,
                       &object) != KERN_SUCCESS)
        return std::nullopt;
    entry.end = entry.start + size;
    entry.tag = info.user_tag;
    return entry;
}

} // namespace

// The VM map keeps no record of which entries one allocation made, so an
// allocation is taken to be the run of entries around the address that touch
// one another and were allocated for the same purpose.
std::pair<Address, Address> PtracePlatformMac::allocationContaining(Address addr) const {
    if (taskPort == MACH_PORT_NULL || addr == 0) return {0, 0};
    auto entry = mapEntryFrom(taskPort, addr);
    if (!entry || entry->start > addr) return {0, 0};

    MapEntry allocation = growForward(*entry);
    while (auto grown = growBackward(allocation)) allocation = *grown;
    return {allocation.start, allocation.end};
}

// The allocation with the entries after it that touch it and were allocated
// for the same thing.
MapEntry PtracePlatformMac::growForward(MapEntry allocation) const {
    while (auto after = mapEntryFrom(taskPort, allocation.end)) {
        if (after->start != allocation.end || after->tag != allocation.tag) break;
        allocation.end = after->end;
    }
    return allocation;
}

// The allocation with the entry in front of it, or nothing when that entry
// does not touch it or was allocated for something else.
std::optional<MapEntry> PtracePlatformMac::growBackward(MapEntry allocation) const {
    if (allocation.start == 0) return std::nullopt;
    auto before = mapEntryFrom(taskPort, allocation.start - 1);
    if (!before || before->start >= allocation.start || before->end != allocation.start
        || before->tag != allocation.tag)
        return std::nullopt;
    allocation.start = before->start;
    return allocation;
}

// Code pages are mapped read-only and executable, so writing a breakpoint
// makes a private, writable copy of the pages it touches, writes, and gives
// them back the protection they had. Taking execute away and not giving it
// back would fault the target on the next instruction it runs from those
// pages. Executed memory also has its instruction cache flushed, so the
// target runs what was written.
Status PtracePlatformMac::writeMemory(Address addr, const void* data, size_t size) {
    if (taskPort == MACH_PORT_NULL) return Status::NotAttached;

    auto protection = protectionAt(taskPort, addr);
    if (!protection) return Status::Error;

    mach_vm_address_t pageStart = mach_vm_trunc_page(addr);
    mach_vm_size_t pagesSize = mach_vm_round_page(addr + size) - pageStart;
    bool writable = (*protection & VM_PROT_WRITE) != 0;
    if (!writable) {
        kern_return_t kr = mach_vm_protect(taskPort, pageStart, pagesSize, false,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) return Status::Error;
    }

    kern_return_t kr = mach_vm_write(
        taskPort,
        static_cast<mach_vm_address_t>(addr),
        reinterpret_cast<vm_offset_t>(data),
        static_cast<mach_msg_type_number_t>(size));

    if (!writable)
        mach_vm_protect(taskPort, pageStart, pagesSize, false, *protection);
    if (kr != KERN_SUCCESS) return Status::Error;

    if (*protection & VM_PROT_EXECUTE) {
        vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
        mach_vm_machine_attribute(taskPort, addr, size, MATTR_CACHE, &flush);
    }
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Register access (Mach thread_get_state / thread_set_state)
// ---------------------------------------------------------------------------

Status PtracePlatformMac::getThreadRegisters(ThreadId tid, const Arch* arch, Registers& out) const {
    thread_act_t port = static_cast<thread_act_t>(tid);

#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state{};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(port, ARM_THREAD_STATE64,
                                        reinterpret_cast<thread_state_t>(&state),
                                        &count);
    if (kr != KERN_SUCCESS) return Status::Error;

    out.arch = ARM64::instance();
    auto& r = out.arm64;
    r.x0  = state.__x[0];  r.x1  = state.__x[1];  r.x2  = state.__x[2];
    r.x3  = state.__x[3];  r.x4  = state.__x[4];  r.x5  = state.__x[5];
    r.x6  = state.__x[6];  r.x7  = state.__x[7];  r.x8  = state.__x[8];
    r.x9  = state.__x[9];  r.x10 = state.__x[10]; r.x11 = state.__x[11];
    r.x12 = state.__x[12]; r.x13 = state.__x[13]; r.x14 = state.__x[14];
    r.x15 = state.__x[15]; r.x16 = state.__x[16]; r.x17 = state.__x[17];
    r.x18 = state.__x[18]; r.x19 = state.__x[19]; r.x20 = state.__x[20];
    r.x21 = state.__x[21]; r.x22 = state.__x[22]; r.x23 = state.__x[23];
    r.x24 = state.__x[24]; r.x25 = state.__x[25]; r.x26 = state.__x[26];
    r.x27 = state.__x[27]; r.x28 = state.__x[28];
    r.x29_fp = arm_thread_state64_get_fp(state);
    r.x30_lr = arm_thread_state64_get_lr(state);
    r.sp     = arm_thread_state64_get_sp(state);
    r.pc     = arm_thread_state64_get_pc(state);

#else // x86_64
    x86_thread_state64_t state{};
    mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(port, x86_THREAD_STATE64,
                                        reinterpret_cast<thread_state_t>(&state),
                                        &count);
    if (kr != KERN_SUCCESS) return Status::Error;

    out.arch = X64::instance();
    auto& r = out.x64;
    r.rax = state.__rax; r.rbx = state.__rbx; r.rcx = state.__rcx; r.rdx = state.__rdx;
    r.rsi = state.__rsi; r.rdi = state.__rdi; r.rbp = state.__rbp; r.rsp = state.__rsp;
    r.r8  = state.__r8;  r.r9  = state.__r9;  r.r10 = state.__r10; r.r11 = state.__r11;
    r.r12 = state.__r12; r.r13 = state.__r13; r.r14 = state.__r14; r.r15 = state.__r15;
    r.rip    = state.__rip;
    r.rflags = state.__rflags;
    r.cs = static_cast<uint16_t>(state.__cs);
    r.fs = static_cast<uint16_t>(state.__fs);
    r.gs = static_cast<uint16_t>(state.__gs);
    r.pc = state.__rip;
    r.sp = state.__rsp;
#endif

    (void)arch;
    return Status::Ok;
}

Status PtracePlatformMac::setThreadPc(ThreadId tid, Address pc) const {
    thread_act_t port = static_cast<thread_act_t>(tid);

#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state{};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(port, ARM_THREAD_STATE64,
                                        reinterpret_cast<thread_state_t>(&state),
                                        &count);
    if (kr != KERN_SUCCESS) return Status::Error;

    arm_thread_state64_set_pc_fptr(state, reinterpret_cast<void*>(pc));
    kr = thread_set_state(port, ARM_THREAD_STATE64,
                          reinterpret_cast<thread_state_t>(&state),
                          ARM_THREAD_STATE64_COUNT);
#else
    x86_thread_state64_t state{};
    mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(port, x86_THREAD_STATE64,
                                        reinterpret_cast<thread_state_t>(&state),
                                        &count);
    if (kr != KERN_SUCCESS) return Status::Error;

    state.__rip = pc;
    kr = thread_set_state(port, x86_THREAD_STATE64,
                          reinterpret_cast<thread_state_t>(&state),
                          x86_THREAD_STATE64_COUNT);
#endif
    return (kr == KERN_SUCCESS) ? Status::Ok : Status::Error;
}

// ---------------------------------------------------------------------------
// Thread enumeration (Mach)
// ---------------------------------------------------------------------------

std::vector<ThreadId> PtracePlatformMac::enumerateThreads() {
    std::vector<ThreadId> result;
    if (taskPort == MACH_PORT_NULL) return result;

    thread_act_array_t threadList = nullptr;
    mach_msg_type_number_t threadCount = 0;
    kern_return_t kr = task_threads(taskPort, &threadList, &threadCount);
    if (kr != KERN_SUCCESS) return result;

    // Release send rights from the previous enumeration
    for (auto port : cachedThreadPorts)
        mach_port_deallocate(mach_task_self(), port);
    cachedThreadPorts.clear();

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        result.push_back(static_cast<ThreadId>(threadList[i]));
        // Keep this send right alive so the port name stays stable
        cachedThreadPorts.push_back(threadList[i]);
    }

    vm_deallocate(mach_task_self(),
                  reinterpret_cast<vm_address_t>(threadList),
                  threadCount * sizeof(thread_act_t));

    return result;
}

// ---------------------------------------------------------------------------
// Module enumeration (dyld image list)
// ---------------------------------------------------------------------------

std::vector<ModuleInfo> PtracePlatformMac::enumerateModules() const {
    std::vector<ModuleInfo> modules;
    if (taskPort == MACH_PORT_NULL) return modules;

    // Get dyld_all_image_infos address via task_info
    struct task_dyld_info dyldInfo{};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(taskPort, TASK_DYLD_INFO,
                                reinterpret_cast<task_info_t>(&dyldInfo), &count);
    if (kr != KERN_SUCCESS) return modules;

    Address infosAddr = dyldInfo.all_image_info_addr;
    if (infosAddr == 0) return modulesMappedByKernel();

    // Read version and infoArrayCount from dyld_all_image_infos.
    // Layout: uint32_t version, uint32_t infoArrayCount, uintptr_t infoArray
    uint32_t version = 0, imageCount = 0;
    uint64_t infoArrayPtr = 0;
    if (readMemory(infosAddr, &version, 4) != Status::Ok) return modules;
    if (readMemory(infosAddr + 4, &imageCount, 4) != Status::Ok) return modules;
    if (readMemory(infosAddr + 8, &infoArrayPtr, 8) != Status::Ok) return modules;

    if (imageCount == 0 || infoArrayPtr == 0) return modulesMappedByKernel();
    if (imageCount > 10000) return modules;

    // Each dyld_image_info is: { const mach_header* imageLoadAddress,
    //                            const char* imageFilePath,
    //                            uintptr_t imageFileModDate }
    // = 3 pointers = 24 bytes on 64-bit
    for (uint32_t i = 0; i < imageCount; i++) {
        readModuleEntry(modules, infoArrayPtr + i * 24);
    }

    // dyld does not list itself, and every thread starts in it.
    uint64_t dyldBase = 0;
    if (readMemory(infosAddr + offsetof(dyld_all_image_infos, dyldImageLoadAddress),
                   &dyldBase, sizeof dyldBase) == Status::Ok && dyldBase != 0) {
        ModuleInfo dyld;
        dyld.path = "/usr/lib/dyld";
        dyld.loadAddress = dyldBase;
        modules.push_back(std::move(dyld));
    }
    return modules;
}

// Before dyld has run its image list is empty, and the modules there are
// are the two the kernel mapped: the executable and dyld itself. They are
// found by their Mach-O headers, at the start of a region.
std::vector<ModuleInfo> PtracePlatformMac::modulesMappedByKernel() const {
    std::vector<ModuleInfo> modules;
    mach_vm_address_t address = 0;
    while (true) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        if (mach_vm_region(taskPort, &address, &size, VM_REGION_BASIC_INFO_64,
                           reinterpret_cast<vm_region_info_t>(&info), &count,
                           &object) != KERN_SUCCESS)
            break;
        addKernelMappedModule(modules, address);
        address += size;
    }
    return modules;
}

void PtracePlatformMac::addKernelMappedModule(std::vector<ModuleInfo>& modules,
                                              Address address) const {
    mach_header_64 header{};
    if (readMemory(address, &header, sizeof header) != Status::Ok) return;
    if (header.magic != MH_MAGIC_64) return;

    ModuleInfo mod;
    mod.loadAddress = address;
    if (header.filetype == MH_EXECUTE) {
        char path[PROC_PIDPATHINFO_MAXSIZE]{};
        if (proc_pidpath(targetPid, path, sizeof path) <= 0) return;
        mod.path = path;
        // First, as dyld lists it once it has run.
        modules.insert(modules.begin(), std::move(mod));
    } else if (header.filetype == MH_DYLINKER) {
        mod.path = "/usr/lib/dyld";
        modules.push_back(std::move(mod));
    }
}

void PtracePlatformMac::readModuleEntry(std::vector<ModuleInfo>& modules,
                                         Address entryAddr) const {
    uint64_t loadAddr = 0, filePathPtr = 0;
    if (readMemory(entryAddr, &loadAddr, 8) != Status::Ok) return;
    if (readMemory(entryAddr + 8, &filePathPtr, 8) != Status::Ok) return;

    // Read the file path string (up to 1024 bytes)
    char pathBuf[1024]{};
    if (filePathPtr != 0)
        readMemory(filePathPtr, pathBuf, sizeof(pathBuf) - 1);
    pathBuf[sizeof(pathBuf) - 1] = '\0';

    ModuleInfo mod;
    mod.path = pathBuf;
    mod.loadAddress = loadAddr;
    mod.slide = 0;
    modules.push_back(std::move(mod));
}

// ---------------------------------------------------------------------------
// Mach exception server
// ---------------------------------------------------------------------------
//
// Why this exists
// ---------------
// PT_ATTACHEXC routes the target task's exception ports through the parent so
// SIGTRAP-style stops (breakpoints / single-step) surface as waitpid events.
// What it does NOT do reliably on modern macOS is convert *fatal* exceptions
// (EXC_BAD_ACCESS = SIGSEGV/SIGBUS, EXC_CRASH = SIGABRT, EXC_BAD_INSTRUCTION,
// EXC_ARITHMETIC, EXC_GUARD) into ptrace stops.  Those bypass waitpid: the
// child gets killed and waitpid returns WIFSIGNALED — at which point it is
// too late to inspect anything.
//
// The canonical fix is to drain the Mach exception port ourselves.  We:
//   1. Allocate a Mach receive port and grant ourselves a send right.
//   2. task_set_exception_ports() on the target with EXC_MASK_ALL pointing
//      at our port (this REPLACES the kernel default-handler chain that
//      PT_ATTACHEXC put in place — and that's intentional).
//   3. Spin up a dedicated thread that does mach_msg(MACH_RCV_MSG) in a loop.
//
// When an exception arrives we:
//   - Hand-decode the message (rather than depending on MIG-generated stubs).
//     The wire format is documented as mach_exception_raise (msg id 2401):
//        mach_msg_header_t
//        mach_msg_body_t body          // descriptor_count
//        mach_msg_port_descriptor_t thread
//        mach_msg_port_descriptor_t task
//        NDR_record_t NDR
//        exception_type_t exception
//        mach_msg_type_number_t codeCnt
//        mach_exception_data_type_t code[2]   // int64_t on 64-bit kernels
//   - Suspend the target task so it stays paused while the debugger inspects.
//   - Hold the exception, in a queue, and DON'T reply to the Mach message: the
//     target stays suspended and the faulting thread frozen in exception state.
//     waitForStop() reports it as a stop, on its thread. Once we've claimed
//     the exception there's no posix signal-stop left for waitpid to wake on,
//     so this cross-thread queue of held exceptions is the only channel back.
//
// EXC_BREAKPOINT / HW watchpoints
// -------------------------------
// Breakpoint and single-step traps normally stay on the ptrace-synthesised
// path, so we don't register EXC_MASK_BREAKPOINT by default. The exception is
// HW watchpoints: when one is configured we add EXC_MASK_BREAKPOINT so the hit
// reaches this server, where the EXC_BREAKPOINT handler runs the
// single-step/re-arm dance and reads the post-store value.

// Wire-format of a mach_exception_raise message we expect to receive.
// Packed so offsets match the kernel's layout exactly.
#pragma pack(push, 4)
struct MachExceptionMessage {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    // Trailer follows but we don't read it.
    char trailer[64];
};
#pragma pack(pop)

namespace {

// Signals the debugger causes itself, which the program never gets.
bool isDebuggerSignal(int signal) {
    return signal == SIGTRAP || signal == SIGSTOP;
}

bool isSignal(int exception, int64_t code) {
    return exception == EXC_SOFTWARE && code == EXC_SOFT_SIGNAL;
}

// Exceptions the kernel turns into a signal for the program when they are
// not handled.
bool isFault(int exception) {
    switch (exception) {
        case EXC_BAD_ACCESS: case EXC_BAD_INSTRUCTION: case EXC_ARITHMETIC:
        case EXC_GUARD: case EXC_CRASH:
            return true;
        default:
            return false;
    }
}

const char* exceptionName(int exception) {
    switch (exception) {
        case EXC_BAD_ACCESS:      return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC:      return "EXC_ARITHMETIC";
        case EXC_SOFTWARE:        return "EXC_SOFTWARE";
        case EXC_BREAKPOINT:      return "EXC_BREAKPOINT";
        case EXC_CRASH:           return "EXC_CRASH";
        case EXC_GUARD:           return "EXC_GUARD";
        default:                  return "EXC_?";
    }
}

// The signal a stop is reported as.
int signalOf(int exception, int64_t code, int64_t subcode) {
    if (isSignal(exception, code)) return static_cast<int>(subcode);
    switch (exception) {
        case EXC_BAD_ACCESS:      return code == KERN_INVALID_ADDRESS ? SIGSEGV : SIGBUS;
        case EXC_BAD_INSTRUCTION: return SIGILL;
        case EXC_ARITHMETIC:      return SIGFPE;
        case EXC_CRASH:           return SIGABRT;
        case EXC_GUARD:           return SIGKILL;
        default:                  return SIGTRAP;
    }
}

struct MachExceptionRaiseReply {
    mach_msg_header_t header;
    NDR_record_t NDR;
    kern_return_t RetCode;
};
} // namespace

Status PtracePlatformMac::startExceptionServer() {
    if (exceptionPort != MACH_PORT_NULL)
        return Status::Ok;  // already running

    kern_return_t kr;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                            &exceptionPort);
    if (kr != KERN_SUCCESS) {
        doLog("(mach) mach_port_allocate failed: " +
              std::string(mach_error_string(kr)));
        exceptionPort = MACH_PORT_NULL;
        return Status::Error;
    }
    kr = mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        doLog("(mach) mach_port_insert_right failed: " +
              std::string(mach_error_string(kr)));
        mach_port_deallocate(mach_task_self(), exceptionPort);
        exceptionPort = MACH_PORT_NULL;
        return Status::Error;
    }
    // Signals come as EXC_SOFTWARE under PT_ATTACHEXC, and breakpoints and
    // steps as EXC_BREAKPOINT: every stop of the target comes here.
    exception_mask_t mask =
        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC |
        EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_CRASH | EXC_MASK_GUARD;
    kr = task_set_exception_ports(taskPort, mask, exceptionPort,
                                  EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                  THREAD_STATE_NONE);
    if (kr != KERN_SUCCESS) {
        doLog("(mach) task_set_exception_ports failed: " +
              std::string(mach_error_string(kr)));
        mach_port_deallocate(mach_task_self(), exceptionPort);
        exceptionPort = MACH_PORT_NULL;
        return Status::Error;
    }
    exceptionThreadStop.store(false);
    exceptionThread = std::thread([this] { this->exceptionServerLoop(); });
    return Status::Ok;
}

void PtracePlatformMac::stopExceptionServer() {
    if (exceptionPort == MACH_PORT_NULL) return;
    exceptionThreadStop.store(true);
    // Wake the receive loop by sending an empty message to ourselves.  The
    // loop checks exceptionThreadStop on every iteration.
    mach_msg_header_t wake{};
    wake.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    wake.msgh_size        = sizeof(wake);
    wake.msgh_remote_port = exceptionPort;
    wake.msgh_local_port  = MACH_PORT_NULL;
    wake.msgh_id          = 0xDEADBEEF;
    mach_msg(&wake, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(wake), 0,
             MACH_PORT_NULL, 100, MACH_PORT_NULL);
    if (exceptionThread.joinable())
        exceptionThread.join();
    // Anything that arrived meanwhile is answered rather than left waiting.
    resumeHeld();
    mach_port_deallocate(mach_task_self(), exceptionPort);
    mach_port_mod_refs(mach_task_self(), exceptionPort, MACH_PORT_RIGHT_RECEIVE, -1);
    exceptionPort = MACH_PORT_NULL;
}

void PtracePlatformMac::logFault(const MachExceptionMessage& msg) const {
    char line[256];
    snprintf(line, sizeof(line),
             "(mach) caught %s code=0x%llx subcode=0x%llx thread=0x%llx",
             exceptionName(msg.exception),
             (unsigned long long)(msg.codeCnt > 0 ? msg.code[0] : 0),
             (unsigned long long)(msg.codeCnt > 1 ? msg.code[1] : 0),
             (unsigned long long)msg.thread.name);
    doLog(line);
}

void PtracePlatformMac::receiveException(const MachExceptionMessage& msg) {
    HeldException exception;
    exception.replyPort = msg.header.msgh_remote_port;
    exception.replyBits = MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits);
    exception.replyId = msg.header.msgh_id + 100;
    exception.thread = msg.thread.name;
    exception.exception = msg.exception;
    exception.code = msg.codeCnt > 0 ? msg.code[0] : 0;
    exception.subcode = msg.codeCnt > 1 ? msg.code[1] : 0;
    mach_port_deallocate(mach_task_self(), msg.task.name);
    if (handleWatchpointException(exception)) return;

    // Suspend the target so it stays paused for the debugger to inspect.
    task_suspend(taskPort);
    if (isFault(exception.exception)) logFault(msg);
    hold(exception);
}

// The task stays suspended and the thread waits for the answer, so the
// target stays where it stopped while the debugger looks at it.
void PtracePlatformMac::hold(const HeldException& exception) {
    {
        std::lock_guard<std::mutex> lock(exceptionMutex);
        held.push_back(exception);
    }
    exceptionCv.notify_all();
}

// Reports the first stop not reported yet, as the signal it stands for, or
// answers 0 when there is none.
int PtracePlatformMac::takeStop() {
    std::lock_guard<std::mutex> lock(exceptionMutex);
    for (auto& exception : held) {
        if (exception.reported) continue;
        exception.reported = true;
        lastStopThread = exception.thread;
        return signalOf(exception.exception, exception.code, exception.subcode);
    }
    return 0;
}

int PtracePlatformMac::waitForStop(int pid, int timeoutMs, int& status) {
    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::milliseconds(std::max(timeoutMs, 0));
    while (true) {
        if (int signal = takeStop()) return signal;
        if (waitpid(pid, &status, WNOHANG) > 0
            && (WIFEXITED(status) || WIFSIGNALED(status)))
            return -2;
        if (timeoutMs >= 0 && std::chrono::steady_clock::now() >= deadline)
            return -1;

        // A process that exits sends no message, so waitpid is asked again
        // at least every 50 ms.
        std::unique_lock<std::mutex> lock(exceptionMutex);
        exceptionCv.wait_for(lock, std::chrono::milliseconds(50), [this] {
            return std::any_of(held.begin(), held.end(),
                               [](const HeldException& e) { return !e.reported; });
        });
    }
}

// Answers every held exception, so the target runs again. A signal is given
// to its thread to deliver, except the SIGTRAP and SIGSTOP the debugger
// caused. A fault is answered with KERN_FAILURE, so the kernel raises the
// signal the program would have got without a debugger.
void PtracePlatformMac::resumeHeld() {
    std::deque<HeldException> answering;
    {
        std::lock_guard<std::mutex> lock(exceptionMutex);
        answering.swap(held);
    }
    for (const auto& exception : answering) {
        if (isSignal(exception.exception, exception.code)) {
            int signal = static_cast<int>(exception.subcode);
            int delivered = isDebuggerSignal(signal) ? 0 : signal;
            ptrace(PT_THUPDATE, targetPid,
                   reinterpret_cast<caddr_t>(static_cast<uintptr_t>(exception.thread)),
                   delivered);
        }
        answer(exception, isFault(exception.exception) ? KERN_FAILURE : KERN_SUCCESS);
        if (taskPort != MACH_PORT_NULL) task_resume(taskPort);
    }
}

void PtracePlatformMac::answer(const HeldException& exception, kern_return_t result) {
    MachExceptionRaiseReply reply{};
    reply.header.msgh_bits = MACH_MSGH_BITS(exception.replyBits, 0);
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_remote_port = exception.replyPort;
    reply.header.msgh_local_port = MACH_PORT_NULL;
    reply.header.msgh_id = exception.replyId;
    reply.NDR = NDR_record;
    reply.RetCode = result;
    mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), static_cast<mach_port_t>(exception.thread));
}

void PtracePlatformMac::exceptionServerLoop() {
    while (!exceptionThreadStop.load()) {
        MachExceptionMessage msg{};
        kern_return_t kr = mach_msg(&msg.header,
                                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0,
                                    sizeof(msg),
                                    exceptionPort,
                                    250,  // 250 ms — keeps shutdown responsive
                                    MACH_PORT_NULL);
        if (kr == MACH_RCV_TIMED_OUT)
            continue;
        if (kr != KERN_SUCCESS) {
            doLog("(mach) mach_msg recv failed: " +
                  std::string(mach_error_string(kr)));
            continue;
        }
        if (msg.header.msgh_id == 0xDEADBEEF)
            break;  // shutdown wakeup

        receiveException(msg);
    }
}

// A watchpoint hit (EXC_BREAKPOINT) traps before the store completes. Two
// phases keep the program's semantics while still observing every write to
// the watched word:
//   A. the hit: log the writer, disable the watchpoint on the thread, step it
//      over the store and let it go;
//   B. the step: the store has happened, so read the value, re-arm the
//      watchpoint and stop only when the value matches what was asked for.
// Answers true when the exception was dealt with and the target goes on.
bool PtracePlatformMac::handleWatchpointException(const HeldException& exception) {
#if defined(__arm64__) || defined(__aarch64__)
    if (exception.exception != EXC_BREAKPOINT) return false;
    mach_port_t thread = static_cast<mach_port_t>(exception.thread);

    if (steppingThreads_.count(thread) == 0) {
        // Breakpoints and steps are stops; only a watchpoint hit is handled here.
        if (watchAddrLive_ == 0 || exception.code != EXC_ARM_DA_DEBUG) return false;
        logWatchpointHit(thread);

        arm_debug_state64_t dbg{};
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, &count);
        dbg.__wcr[0] = 0;
        thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, count);
        setSingleStep(thread, true);
        steppingThreads_.insert(thread);
        answer(exception, KERN_SUCCESS);
        return true;
    }

    steppingThreads_.erase(thread);
    setSingleStep(thread, false);
    uint64_t value = 0;
    readMemory(watchAddrLive_, &value, sizeof value);
    char line[160];
    snprintf(line, sizeof(line), "(watch)   post-store value=0x%llx",
             (unsigned long long)value);
    doLog(line);
    if (watchAddrLive_ != 0) installWatchpointOnThread(thread, watchAddrLive_);

    bool matches = watchMatchLive_ != 0
                   && (value & watchMaskLive_) == watchMatchLive_;
    if (matches) return false;
    answer(exception, KERN_SUCCESS);
    return true;
#else
    (void)exception;
    return false;
#endif
}

// Logs where a watchpoint hit happened, with the frames above it.
void PtracePlatformMac::logWatchpointHit(mach_port_t thread) {
#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state{};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    char line[160];
    snprintf(line, sizeof(line),
             "(watch) hit pc=0x%llx lr=0x%llx fp=0x%llx sp=0x%llx (pre-store)",
             (unsigned long long)arm_thread_state64_get_pc(state),
             (unsigned long long)arm_thread_state64_get_lr(state),
             (unsigned long long)arm_thread_state64_get_fp(state),
             (unsigned long long)arm_thread_state64_get_sp(state));
    doLog(line);

    // Each AArch64 frame record is [previous fp][return address].
    uint64_t fp = arm_thread_state64_get_fp(state);
    for (int depth = 0; depth < 6 && fp != 0; depth++) {
        uint64_t record[2] = {0, 0};
        if (readMemory(fp, record, sizeof record) != Status::Ok) break;
        snprintf(line, sizeof(line), "(watch)   frame[%d] fp=0x%llx lr=0x%llx",
                 depth, (unsigned long long)fp, (unsigned long long)record[1]);
        doLog(line);
        if (record[0] <= fp) break;
        fp = record[0];
    }
#else
    (void)thread;
#endif
}

// ARM64 HW watchpoint installer.
//
// Sets debug watchpoint slot 0 on `thread` to break on STORE to the 8 bytes
// starting at `addr` (must be 8-byte aligned). DBGWCR layout:
//   bit 0       E   = 1   (enable)
//   bits 1-2    PAC = 0b10 (EL0 / user-mode only)
//   bits 3-4    LSC = 0b10 (store)
//   bits 5-12   BAS = 0xFF (all 8 bytes match)
// All other fields = 0.
//
// Result: thread traps with EXC_BREAKPOINT (subcode = watchpoint addr) on
// first write touching the watched word. Our Mach handler catches it and
// dumps registers, so we can identify the writer.
void PtracePlatformMac::installWatchpointOnThread(mach_port_t thread, uint64_t addr) {
#if !(defined(__arm64__) || defined(__aarch64__))
    (void)thread; (void)addr;
    doLog("(watch) hardware watchpoints are only implemented for ARM64");
#else
    if (addr & 7) {
        doLog("(watch) address not 8-byte aligned, ignoring");
        return;
    }
    arm_debug_state64_t dbg{};
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&dbg, &cnt);
    if (kr != KERN_SUCCESS) {
        doLog("(watch) thread_get_state failed: " +
              std::string(mach_error_string(kr)));
        return;
    }
    dbg.__wvr[0] = addr;
    // Enable (1) | PAC=EL0 (0b10<<1) | LSC=store (0b10<<3) | BAS=all (0xFF<<5)
    dbg.__wcr[0] = 0x1 | (0x2 << 1) | (0x2 << 3) | (0xFF << 5);
    cnt = ARM_DEBUG_STATE64_COUNT;
    kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                          (thread_state_t)&dbg, cnt);
    if (kr != KERN_SUCCESS) {
        doLog("(watch) thread_set_state failed: " +
              std::string(mach_error_string(kr)));
        return;
    }
    char buf[128];
    snprintf(buf, sizeof(buf),
             "(watch) armed thread=0x%x addr=0x%llx (store, 8 bytes)",
             (unsigned)thread, (unsigned long long)addr);
    doLog(buf);
#endif
}

void PtracePlatformMac::installWatchpointAllThreads(uint64_t addr) {
#if !(defined(__arm64__) || defined(__aarch64__))
    if (addr != 0) installWatchpointOnThread(MACH_PORT_NULL, addr);
#else
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    kern_return_t kr = task_threads(taskPort, &threads, &count);
    if (kr != KERN_SUCCESS) {
        doLog("(watch) task_threads failed: " +
              std::string(mach_error_string(kr)));
        return;
    }
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (addr == 0) {
            arm_debug_state64_t dbg{};
            mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
            thread_get_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&dbg, &cnt);
            dbg.__wcr[0] = 0;
            thread_set_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&dbg, cnt);
        } else {
            installWatchpointOnThread(threads[i], addr);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  count * sizeof(thread_act_t));
#endif
}

// Runtime setter. addr=0 clears the watchpoint. match=0 means "never break,
// just log every hit". Bits in `mask` (default 0xFFFFFFFFFFFFFFFF) constrain
// the comparison: stops when (postValue & mask) == match.
void PtracePlatformMac::setWatchpoint(uint64_t addr, uint64_t match, uint64_t mask) {
    watchAddrLive_ = addr;
    watchMatchLive_ = match;
    watchMaskLive_ = mask ? mask : 0xFFFFFFFFFFFFFFFFULL;
    installWatchpointAllThreads(addr);  // 0 → clears
    char buf[160];
    snprintf(buf, sizeof(buf),
             "(watch) setWatchpoint addr=0x%llx match=0x%llx mask=0x%llx",
             (unsigned long long)addr, (unsigned long long)match,
             (unsigned long long)watchMaskLive_);
    doLog(buf);
}

} // namespace smalldbg
