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
                                    const std::vector<std::string>& args) {
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

    pid_t child = -1;
    int spawn_rc = posix_spawn(&child, path.c_str(), nullptr, &attr,
                               argv.data(), *_NSGetEnviron());
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

    // Install Mach exception ports through ptrace so future stops surface via
    // waitpid the way they do on Linux.
    if (ptrace(PT_ATTACHEXC, child, nullptr, 0) < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "(ptrace) PT_ATTACHEXC failed: %s", strerror(errno));
        doLog(buf);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return -1;
    }

    // After PT_ATTACHEXC the kernel may push an additional stop event onto
    // the queue. Drain it with a non-blocking waitpid so the child is in a
    // clean stopped state when we return.
    waitpid(child, &status, WNOHANG | WUNTRACED);

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
    int result = ptrace(PT_CONTINUE, pid, reinterpret_cast<caddr_t>(1), 0);
    if (result < 0)
        doLog("(ptrace) PT_CONTINUE failed: " + std::string(strerror(errno)));
    return result;
}

int PtracePlatformMac::ptraceStep(int pid) {
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
    targetPid = pid;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &taskPort);
    if (kr != KERN_SUCCESS) {
        doLog("(ptrace) task_for_pid failed: " + std::string(mach_error_string(kr))
              + " (requires sudo or com.apple.security.cs.debugger entitlement)");
        return Status::Error;
    }
    // Install a Mach exception server so EXC_BAD_ACCESS / EXC_BAD_INSTRUCTION /
    // EXC_CRASH etc. surface to the debugger instead of terminating the child.
    // Failure here is non-fatal — we fall back to the existing PT_ATTACHEXC
    // path which only catches SIGTRAP (breakpoints/single-step).
    if (startExceptionServer() != Status::Ok)
        doLog("(ptrace) Mach exception server failed to start; fatal signals "
              "will terminate the child silently");

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
    stopExceptionServer();

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

Status PtracePlatformMac::writeMemory(Address addr, const void* data, size_t size) {
    if (taskPort == MACH_PORT_NULL) return Status::NotAttached;

    // Mach VM write may need the region to be writable.  Try to set
    // VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY first; if the region is
    // already writable this is a harmless no-op.
    mach_vm_protect(taskPort,
                    static_cast<mach_vm_address_t>(addr & ~0xFFFULL),
                    0x1000,
                    false,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    kern_return_t kr = mach_vm_write(
        taskPort,
        static_cast<mach_vm_address_t>(addr),
        reinterpret_cast<vm_offset_t>(data),
        static_cast<mach_msg_type_number_t>(size));

    if (kr != KERN_SUCCESS) return Status::Error;
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
    if (infosAddr == 0) return modules;

    // Read version and infoArrayCount from dyld_all_image_infos.
    // Layout: uint32_t version, uint32_t infoArrayCount, uintptr_t infoArray
    uint32_t version = 0, imageCount = 0;
    uint64_t infoArrayPtr = 0;
    if (readMemory(infosAddr, &version, 4) != Status::Ok) return modules;
    if (readMemory(infosAddr + 4, &imageCount, 4) != Status::Ok) return modules;
    if (readMemory(infosAddr + 8, &infoArrayPtr, 8) != Status::Ok) return modules;

    if (imageCount == 0 || imageCount > 10000 || infoArrayPtr == 0) return modules;

    // Each dyld_image_info is: { const mach_header* imageLoadAddress,
    //                            const char* imageFilePath,
    //                            uintptr_t imageFileModDate }
    // = 3 pointers = 24 bytes on 64-bit
    for (uint32_t i = 0; i < imageCount; i++) {
        readModuleEntry(modules, infoArrayPtr + i * 24);
    }
    return modules;
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
//   - Save a PendingException record and DON'T reply to the Mach message: the
//     target stays suspended and the faulting thread frozen in exception state.
//     PtraceBackend::waitForEvent polls pollAsyncException() to pick this up and
//     turn it into a normal Exception stop. Once we've claimed the exception
//     there's no posix signal-stop left for waitpid to wake on, so this
//     cross-thread PendingException hand-off is the only channel back.
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
namespace {
struct MachExceptionRaiseMessage {
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
    // Route fatal task-level exceptions to us. EXC_BREAKPOINT is included
    // when a HW watchpoint is configured — without it the kernel would
    // deliver watchpoint hits to the previous (ptrace) handler instead of
    // ours, and we'd lose the rich register dump the Mach handler can do.
    exception_mask_t mask =
        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_ARITHMETIC | EXC_MASK_CRASH | EXC_MASK_GUARD;
    if (std::getenv("SMALLDBG_WATCH_ADDR"))
        mask |= EXC_MASK_BREAKPOINT;
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
    mach_port_deallocate(mach_task_self(), exceptionPort);
    exceptionPort = MACH_PORT_NULL;
}

void PtracePlatformMac::exceptionServerLoop() {
    while (!exceptionThreadStop.load()) {
        MachExceptionRaiseMessage msg{};
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

        // Suspend the target so it stays paused for the debugger to inspect.
        // It's almost certainly already suspended (the kernel pauses the
        // crashing thread while awaiting our reply), but be defensive.
        task_suspend(taskPort);

        long subcode = msg.codeCnt > 1 ? msg.code[1] : 0;
        {
            std::lock_guard<std::mutex> lk(exceptionMutex);
            pending_.present   = true;
            pending_.exception = msg.exception;
            pending_.code      = msg.codeCnt > 0 ? msg.code[0] : 0;
            pending_.subcode   = subcode;
            pending_.thread    = msg.thread.name;
        }
        // Surface a one-liner so the user sees the precise fault even when
        // the backend's downstream signal-stop handler reports only "signal N".
        const char* name = "EXC_?";
        switch (msg.exception) {
            case EXC_BAD_ACCESS:      name = "EXC_BAD_ACCESS";      break;
            case EXC_BAD_INSTRUCTION: name = "EXC_BAD_INSTRUCTION"; break;
            case EXC_ARITHMETIC:      name = "EXC_ARITHMETIC";      break;
            case EXC_CRASH:           name = "EXC_CRASH";           break;
            case EXC_GUARD:           name = "EXC_GUARD";           break;
            case EXC_BREAKPOINT:      name = "EXC_BREAKPOINT (watchpoint)"; break;
        }
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "(mach) caught %s code=0x%lx subcode=0x%lx thread=0x%llx",
                 name, pending_.code, pending_.subcode,
                 (unsigned long long)pending_.thread);
        doLog(buf);

        // Dump the faulting thread's ARM64 register state so we can identify
        // which object/slot is bad without needing the backend's downstream
        // getRegisters to work (it doesn't, because SIGSTOP isn't the
        // "expected" stop reason the backend was built for).
        arm_thread_state64_t state{};
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        kern_return_t gkr = thread_get_state(msg.thread.name,
                                             ARM_THREAD_STATE64,
                                             (thread_state_t)&state, &cnt);
        if (gkr == KERN_SUCCESS) {
            // Emit each line separately so doLog doesn't truncate at first \n.
            char rb[256];
            snprintf(rb, sizeof(rb), "(mach) pc=0x%llx lr=0x%llx fp=0x%llx sp=0x%llx",
                (unsigned long long)state.__pc, (unsigned long long)state.__lr,
                (unsigned long long)state.__fp, (unsigned long long)state.__sp);
            doLog(rb);
            for (int i = 0; i < 29; i += 4) {
                snprintf(rb, sizeof(rb),
                    "(mach) x%d=0x%llx x%d=0x%llx x%d=0x%llx x%d=0x%llx",
                    i,   (unsigned long long)state.__x[i],
                    i+1, (unsigned long long)state.__x[i+1],
                    i+2, (unsigned long long)state.__x[i+2],
                    i+3, (unsigned long long)state.__x[i+3]);
                doLog(rb);
            }
            // Try to dump 64 bytes at x0 (typical 'this' / first arg).
            // The faulting address (subcode/code depending on cpu) is what
            // we *can't* read; dumping x0 helps identify which slot value
            // is stale when the crash is reading the header of `*x0`.
        } else {
            doLog("(mach) thread_get_state failed: " +
                  std::string(mach_error_string(gkr)));
        }

        // EXC_BREAKPOINT (HW watchpoint hit OR software-step completion).
        //
        // Two-phase state machine:
        //
        //   Phase A: real watchpoint hit (thread NOT in steppingThreads_).
        //     1. Log writer PC/LR (post-write value isn't valid yet — store
        //        hasn't completed). Save the PC.
        //     2. Disable the HW watchpoint on this thread.
        //     3. Set ARM64 software-step bits (MDSCR_EL1.SS + PSTATE.SS=1).
        //     4. Mark thread as stepping, reply KERN_SUCCESS, resume.
        //        The kernel executes ONE instruction (the trapping store)
        //        with the watchpoint disabled — so the store actually
        //        completes — then raises another EXC_BREAKPOINT for the
        //        step.
        //
        //   Phase B: step completion (thread IS in steppingThreads_).
        //     1. NOW the store has happened — read the post-write value
        //        at the watched address.
        //     2. Clear ARM64 step bits.
        //     3. Re-arm the HW watchpoint.
        //     4. Match check: stop if (value & mask) == match. Else log
        //        the value, clear pending, reply KERN_SUCCESS, resume.
        //
        // This preserves program semantics (the store actually happens)
        // while still letting us observe every write to the watched word.
        if (msg.exception == EXC_BREAKPOINT) {
            mach_port_t thr = msg.thread.name;
            bool isStep = steppingThreads_.count(thr) > 0;
            if (!isStep) {
                // Phase A: real watchpoint hit. The store hasn't happened
                // yet (HW watchpoint fires synchronously before the store
                // completes). Don't try to read the post-write value here
                // — read it in Phase B after the step.
                arm_thread_state64_t ts{};
                mach_msg_type_number_t tcnt = ARM_THREAD_STATE64_COUNT;
                thread_get_state(thr, ARM_THREAD_STATE64,
                                 (thread_state_t)&ts, &tcnt);
                static int hitCount = 0;
                hitCount++;
                char buf[256];
                snprintf(buf, sizeof(buf),
                    "(watch) hit #%d pc=0x%llx lr=0x%llx fp=0x%llx sp=0x%llx (pre-store)",
                    hitCount,
                    (unsigned long long)ts.__pc,
                    (unsigned long long)ts.__lr,
                    (unsigned long long)ts.__fp,
                    (unsigned long long)ts.__sp);
                doLog(buf);
                // Walk the ARM64 frame chain to give us a 6-deep backtrace.
                // Each frame on AArch64: [x29 (prev FP)][LR]. We read the
                // child's task memory directly via mach_vm_read since this
                // thread is suspended in the exception.
                {
                    uint64_t fp = ts.__fp;
                    for (int depth = 0; depth < 6 && fp != 0; depth++) {
                        struct { uint64_t prevFp; uint64_t savedLr; } frame{};
                        vm_size_t got = 0;
                        vm_offset_t data = 0;
                        kern_return_t rk = mach_vm_read(taskPort, fp,
                                                        sizeof(frame), &data,
                                                        (mach_msg_type_number_t*)&got);
                        if (rk != KERN_SUCCESS || got < sizeof(frame)) break;
                        frame = *(decltype(frame)*)data;
                        vm_deallocate(mach_task_self(), data, got);
                        char fbuf[160];
                        snprintf(fbuf, sizeof(fbuf),
                            "(watch)   frame[%d] fp=0x%llx lr=0x%llx",
                            depth, (unsigned long long)fp,
                            (unsigned long long)frame.savedLr);
                        doLog(fbuf);
                        // Sanity: stop if frame doesn't grow upward sensibly.
                        if (frame.prevFp <= fp) break;
                        fp = frame.prevFp;
                    }
                }

                // Disable watchpoint AND set single-step bits.
                arm_debug_state64_t dbg{};
                mach_msg_type_number_t dcnt = ARM_DEBUG_STATE64_COUNT;
                thread_get_state(thr, ARM_DEBUG_STATE64,
                                 (thread_state_t)&dbg, &dcnt);
                dbg.__wcr[0] = 0;
                dbg.__mdscr_el1 |= 0x1; // SS
                thread_set_state(thr, ARM_DEBUG_STATE64,
                                 (thread_state_t)&dbg, dcnt);
                // Also set PSTATE.SS (bit 21 of CPSR) so the kernel
                // single-steps after this exception is dismissed.
                ts.__cpsr |= (1u << 21);
                tcnt = ARM_THREAD_STATE64_COUNT;
                thread_set_state(thr, ARM_THREAD_STATE64,
                                 (thread_state_t)&ts, tcnt);
                steppingThreads_.insert(thr);
                MachExceptionRaiseReply reply{};
                reply.header.msgh_bits = MACH_MSGH_BITS(
                    MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0);
                reply.header.msgh_size = sizeof(reply);
                reply.header.msgh_remote_port = msg.header.msgh_remote_port;
                reply.header.msgh_local_port = MACH_PORT_NULL;
                reply.header.msgh_id = msg.header.msgh_id + 100;
                reply.NDR = msg.NDR;
                reply.RetCode = KERN_SUCCESS;
                mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                {
                    std::lock_guard<std::mutex> lk(exceptionMutex);
                    pending_ = PendingException{};
                }
                task_resume(taskPort);
                continue;
            }
            // Phase B: step completion. The store has now executed.
            steppingThreads_.erase(thr);
            // Read post-write value.
            uint64_t curValue = 0;
            if (watchAddrLive_) {
                vm_size_t got = 0;
                vm_offset_t data = 0;
                kern_return_t rk = mach_vm_read(taskPort, watchAddrLive_,
                                                sizeof(uint64_t), &data,
                                                (mach_msg_type_number_t*)&got);
                if (rk == KERN_SUCCESS) {
                    curValue = *(uint64_t*)data;
                    vm_deallocate(mach_task_self(), data, got);
                }
            }
            char buf[160];
            snprintf(buf, sizeof(buf),
                "(watch)   post-store value=0x%llx",
                (unsigned long long)curValue);
            doLog(buf);
            // Clear single-step bits AND re-arm watchpoint.
            arm_debug_state64_t dbg{};
            mach_msg_type_number_t dcnt = ARM_DEBUG_STATE64_COUNT;
            thread_get_state(thr, ARM_DEBUG_STATE64,
                             (thread_state_t)&dbg, &dcnt);
            dbg.__mdscr_el1 &= ~uint64_t(0x1);
            if (watchAddrLive_) {
                dbg.__wvr[0] = watchAddrLive_;
                dbg.__wcr[0] = 0x1 | (0x2 << 1) | (0x2 << 3) | (0xFF << 5);
            }
            thread_set_state(thr, ARM_DEBUG_STATE64,
                             (thread_state_t)&dbg, dcnt);
            // Clear PSTATE.SS too.
            arm_thread_state64_t ts{};
            mach_msg_type_number_t tcnt = ARM_THREAD_STATE64_COUNT;
            thread_get_state(thr, ARM_THREAD_STATE64,
                             (thread_state_t)&ts, &tcnt);
            ts.__cpsr &= ~uint32_t(1u << 21);
            tcnt = ARM_THREAD_STATE64_COUNT;
            thread_set_state(thr, ARM_THREAD_STATE64,
                             (thread_state_t)&ts, tcnt);
            // Match check.
            bool stop = (watchMatchLive_ != 0) &&
                        ((curValue & watchMaskLive_) == watchMatchLive_);
            if (!stop) {
                MachExceptionRaiseReply reply{};
                reply.header.msgh_bits = MACH_MSGH_BITS(
                    MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0);
                reply.header.msgh_size = sizeof(reply);
                reply.header.msgh_remote_port = msg.header.msgh_remote_port;
                reply.header.msgh_local_port = MACH_PORT_NULL;
                reply.header.msgh_id = msg.header.msgh_id + 100;
                reply.NDR = msg.NDR;
                reply.RetCode = KERN_SUCCESS;
                mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                {
                    std::lock_guard<std::mutex> lk(exceptionMutex);
                    pending_ = PendingException{};
                }
                task_resume(taskPort);
                continue;
            }
            // Match — fall through to "stay stopped" so debugger inspects.
        }

        // Don't reply to the Mach message and don't task_resume. The task
        // is suspended; the faulting thread is frozen in exception state.
        // Backend polls pollAsyncException() to surface this as a normal
        // Exception stop the rest of the debugger machinery handles.
    }
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
}

void PtracePlatformMac::installWatchpointAllThreads(uint64_t addr) {
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

PtracePlatformMac::PendingException PtracePlatformMac::takePendingException() {
    std::lock_guard<std::mutex> lk(exceptionMutex);
    PendingException out = pending_;
    pending_ = PendingException{};
    return out;
}

PtracePlatform::AsyncException PtracePlatformMac::pollAsyncException() {
    std::lock_guard<std::mutex> lk(exceptionMutex);
    AsyncException out;
    if (pending_.present) {
        out.present   = true;
        out.thread    = pending_.thread;
        out.exception = pending_.exception;
        out.code      = pending_.code;
        out.subcode   = pending_.subcode;
        pending_ = PendingException{};
    }
    return out;
}

} // namespace smalldbg
