#pragma once

#include "Backend.h"
#include "../../include/smalldbg/Arch.h"
#include <vector>
#include <cstdint>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <atomic>
#include <windows.h>
#include <dbgeng.h>

namespace smalldbg {

class DbgEngBackend;  // forward declaration for event callbacks

/// Event callbacks — the engine calls into these during WaitForEvent.
/// Each callback sets stopReason on the backend.
/// Returning DEBUG_STATUS_BREAK causes WaitForEvent to return S_OK.
/// Returning DEBUG_STATUS_GO / GO_NOT_HANDLED lets the engine continue
/// internally (WaitForEvent keeps waiting).
class DbgEngEventCallbacks : public DebugBaseEventCallbacks {
public:
    explicit DbgEngEventCallbacks(DbgEngBackend* be) : backend(be) {}

    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;
    HRESULT STDMETHODCALLTYPE GetInterestMask(ULONG* mask) override;
    HRESULT STDMETHODCALLTYPE Breakpoint(IDebugBreakpoint* bp) override;
    HRESULT STDMETHODCALLTYPE Exception(EXCEPTION_RECORD64* ex, ULONG firstChance) override;
    HRESULT STDMETHODCALLTYPE CreateThread(ULONG64 handle, ULONG64 dataOffset, ULONG64 startOffset) override;
    HRESULT STDMETHODCALLTYPE ExitThread(ULONG exitCode) override;
    HRESULT STDMETHODCALLTYPE CreateProcess(ULONG64 imageFileHandle, ULONG64 handle, ULONG64 baseOffset,
                          ULONG moduleSize, PCSTR moduleName, PCSTR imageName,
                          ULONG checkSum, ULONG timeDateStamp,
                          ULONG64 initialThreadHandle, ULONG64 threadDataOffset,
                          ULONG64 startOffset) override;
    HRESULT STDMETHODCALLTYPE ExitProcess(ULONG exitCode) override;
    HRESULT STDMETHODCALLTYPE LoadModule(ULONG64 imageFileHandle, ULONG64 baseOffset, ULONG moduleSize,
                       PCSTR moduleName, PCSTR imageName,
                       ULONG checkSum, ULONG timeDateStamp) override;
    HRESULT STDMETHODCALLTYPE UnloadModule(PCSTR imageName, ULONG64 baseOffset) override;

private:
    DbgEngBackend* backend;
};

/// Debugging backend that uses the DbgEng (WinDbg) engine.
///
/// This is an alternative to the plain-WinAPI WindowsBackend.  It requires
/// same-architecture debugging: x86 debugger for x86 targets, x64 for x64,
/// ARM64 for ARM64.  Cross-architecture debugging is NOT supported.
class DbgEngBackend : public Backend {
public:
    DbgEngBackend(Debugger* dbg, Mode m, const Arch* a);
    ~DbgEngBackend() override;

    // --- Backend interface ---
    Status attach(uintptr_t pid) override;
    Status launch(const std::string& path, const std::vector<std::string>& args) override;
    Status detach() override;

    Status resume() override;
    Status step(Thread* thread) override;
    Status suspend() override;
    
    // --- TTD (Time Travel Debugging) ---
    Status openTrace(const std::string& tracePath) override;
    Status stepBack(Thread* thread) override;
    Status reverseResume() override;
    bool isTTDTrace() const override { return isTTD; }

    Status setBreakpoint(Address addr, const std::string& name) override;
    Status clearBreakpoint(Address addr) override;
    std::vector<Breakpoint> listBreakpoints() const override;

    Status readMemory(Address address, void* outBuf, size_t size) const override;
    Status writeMemory(Address address, const void* data, size_t size) override;
    Status getRegisters(Thread* thread, Registers& out) const override;
    Status recoverCallerRegisters(Registers& regs) const override;

    StopReason getStopReason() const override { return stopReason; }
    bool isStopped() const override { return stopped; }
    Address getStopAddress() const override { return stopAddress; }
    StopReason waitForEvent(StopReason reason = StopReason::None, int timeout_ms = -1) override;

    bool isAttached() const override { return attached; }

    // Execute a raw DbgEng command (e.g. "kb", "lm") and return output.
    std::string executeCommand(const std::string& cmd) const override;

    // Access to underlying DbgEng interfaces (for potential symbol backend use)
    IDebugSymbols3* getDbgEngSymbols() const { return symbols; }
    IDebugDataSpaces4* getDbgEngDataSpaces() const { return dataSpaces; }

    // Callbacks invoked by the DbgEngEventCallbacks helper (friend).
    void onBreakpoint(ULONG64 offset);
    void onException(DWORD code, ULONG64 address);

    // Called by Exception callback to tell the event loop how to continue
    // uninteresting exceptions (GO_NOT_HANDLED for first-chance, GO for
    // second-chance).  0 means the event loop should stop normally.
    void setPendingExceptionContinue(ULONG status) { pendingContinueStatus = status; }
    bool isStepPending() const { return stepPending; }
    bool onThreadCreated();     // returns true if event callback wants to break
    void onProcessCreated(const std::string& imageName);
    void onProcessExit(ULONG exitCode);
    bool onModuleLoaded(ULONG64 base, ULONG size, const char* moduleName, const char* imageName);
    void onModuleUnloaded(ULONG64 base, const char* imageName);

private:
    // Initialise the COM interfaces. Returns false on failure.
    bool initInterfaces();
    void releaseInterfaces();

    // The debug event pump (runs on its own thread).
    void eventLoop();

    // Populate stop state from the current engine state.
    void captureStopState();

    // --- Event loop phases (called from eventLoop) ---
    // Phase 1: session initialisation
    bool initSession();        // top-level init, returns false on failure
    bool initLaunch();         // launch a child process
    bool initAttach();         // attach to an existing process
    bool initOpenTrace();      // open a TTD trace file
    bool initArchAndRegisters();  // validate target arch, resolve register indices
    void registerSymbolBackend();  // register DbgEngSymbolBackend
    void enumerateInitialThreads();

    // Phase 2: main loop helpers
    bool waitForResumeSignal();  // wait for resume/step, false → exit
    void beginExecution(ULONG& execStatus);  // set execution status on engine
    void pumpEvents(ULONG execStatus);       // inner WaitForEvent pump
    enum class EventAction { Continue, Stop, EndOfTrace, SessionEnded };
    EventAction handleDebugEvent(ULONG execStatus, ULONG64 pc);  // classify & act on one event

    // --- COM interfaces (created on event loop thread) ---
    // Safe to use from any thread when the target is stopped (event loop
    // is parked on cv.wait, so there is no concurrent access).
    IDebugClient5*         client      = nullptr;
    IDebugControl4*        control     = nullptr;
    IDebugRegisters2*      registers   = nullptr;
    IDebugDataSpaces4*     dataSpaces  = nullptr;
    IDebugSymbols3*        symbols     = nullptr;
    IDebugSystemObjects4*  sysObjects  = nullptr;
    IDebugAdvanced3*       advanced    = nullptr;

    // Event callbacks (owned, lives for the session).
    std::unique_ptr<DbgEngEventCallbacks> eventCallbacksImpl;

    // --- Process state ---
    bool attached = false;
    bool isTTD = false;  // True if replaying a TTD trace

    // --- Event thread ---
    std::thread eventThread;
    std::atomic<bool> running{false};

    // --- Deferred launch/attach (event loop performs actual init) ---
    std::string launchPath;
    std::vector<std::string> launchArgs;
    uintptr_t attachPid = 0;
    enum class InitMode { None, Launch, Attach, OpenTrace };
    InitMode initMode = InitMode::None;
    std::string tracePath;  // for InitMode::OpenTrace
    bool initOk = false;
    std::mutex initMutex;
    std::condition_variable initCv;
    bool initDone = false;

    // --- Stop state (protected by mutex) ---
    mutable std::mutex mutex;
    std::condition_variable cv;
    bool stopped          = false;
    StopReason stopReason = StopReason::None;
    Address stopAddress   = 0;
    bool continueRequested= false;
    bool stepRequested    = false;
    DWORD stepThreadId    = 0;
    ULONG pendingExecStatus = 0;              // execution status for event loop (e.g. DEBUG_STATUS_GO)
    ULONG pendingContinueStatus = 0; // non-zero → auto-continue exception
    Address lastStepPC = 0;          // PC before last step (for TTD breakpoint skip)
    bool stepPending = false;         // true while a step is being executed

    // --- Breakpoints ---
    // DbgEng manages breakpoints for us; we keep a parallel list for
    // listBreakpoints() and to map engine BP ids ↔ addresses.
    struct BpInfo {
        Address addr;
        std::string name;
        unsigned long engineId; // IDebugBreakpoint id
    };
    mutable std::mutex bpMutex;
    std::vector<BpInfo> breakpoints;

    // --- Register indices (per-architecture) ---
    // Resolved once after attach via ri.resolve().
    // Maps architecture register names to DbgEng register indices
    // so getRegisters() can call IDebugRegisters2::GetValue by index.
    static constexpr unsigned long INVALID = ~0u;

    struct RegIndices : RegisterReader {
        bool ready = false;
        IDebugRegisters2* regs = nullptr;

        // x64
        unsigned long rip = INVALID, rsp = INVALID, rbp = INVALID, rflags = INVALID;
        unsigned long rax = INVALID, rbx = INVALID, rcx = INVALID, rdx = INVALID;
        unsigned long rsi = INVALID, rdi = INVALID;
        unsigned long r8  = INVALID, r9  = INVALID, r10 = INVALID, r11 = INVALID;
        unsigned long r12 = INVALID, r13 = INVALID, r14 = INVALID, r15 = INVALID;

        // x86
        unsigned long eip = INVALID, esp = INVALID, ebp = INVALID, eflags = INVALID;
        unsigned long eax = INVALID, ebx = INVALID, ecx = INVALID, edx = INVALID;
        unsigned long esi = INVALID, edi = INVALID;

        // ARM64
        unsigned long pc = INVALID, sp = INVALID, fp = INVALID, lr = INVALID, cpsr = INVALID;
        unsigned long x[29] = {};

        // Resolve all indices from the engine.  Call once after attach.
        void resolve(IDebugRegisters2* r);

        // Read a single register value by index; returns 0 for INVALID.
        uint64_t readReg(unsigned long index) const;

        // Populate an architecture-specific register struct from engine state.
        void readX64Regs(X64Registers& out) const override;
        void readX86Regs(X86Registers& out) const override;
        void readARM64Regs(ARM64Registers& out) const override;

    private:
        // Look up a register name; returns INVALID if not present.
        unsigned long idx(const char* name) const;
    };

    mutable RegIndices ri;

    // Track if the first breakpoint has been seen (loader break)
    bool seenInitialBreakpoint = false;
};

} // namespace smalldbg
