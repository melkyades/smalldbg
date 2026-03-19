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
#include <cstring>
#include <sys/ptrace.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

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
    return ptrace(PT_TRACE_ME, 0, nullptr, 0);
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
    return Status::Ok;
}

void PtracePlatformMac::releaseProcess() {
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

} // namespace smalldbg
