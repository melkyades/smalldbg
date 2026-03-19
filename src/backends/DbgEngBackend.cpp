// DbgEngBackend — DbgEng-based debugging backend.
//
// This backend uses the DbgEng (WinDbg) engine exclusively.  It is the
// primary Windows backend for same-architecture debugging (x86/x86, x64/x64,
// ARM64/ARM64).  Cross-architecture debugging is NOT supported.
//
// The event loop is modelled directly on WindowsBackend::debugLoop() — a
// single loop that waits for events, dispatches them, optionally stops and
// waits for resume/step, then continues.

#include "DbgEngBackend.h"

#include "../../include/smalldbg/Process.h"
#include "../../include/smalldbg/Thread.h"
#include "../../include/smalldbg/Debugger.h"

#include "../symbols/DbgEngSymbolBackend.h"

#include <algorithm>
#include <sstream>
#include <string>

#include <windows.h>

// We use dynamic loading for dbgeng.dll to support:
// 1. SDK's dbgeng.dll for normal debugging
// 2. WinDbg Preview's dbgeng.dll for TTD support (has built-in TTD)
// DO NOT link statically: no #pragma comment(lib, "dbgeng.lib")

typedef HRESULT (STDAPICALLTYPE *PFN_DebugCreate)(REFIID InterfaceId, PVOID* Interface);

// The loaded dbgeng module and DebugCreate function pointer
static HMODULE g_dbgengModule = nullptr;
static PFN_DebugCreate g_pfnDebugCreate = nullptr;
static bool g_usingWinDbgPreview = false;

// Load dbgeng.dll dynamically - prefer SDK version for normal use
static bool ensureDbgEngLoaded() {
    if (g_pfnDebugCreate) return true;
    
    // Try loading the system/SDK dbgeng.dll
    g_dbgengModule = LoadLibraryA("dbgeng.dll");
    if (g_dbgengModule) {
        g_pfnDebugCreate = (PFN_DebugCreate)GetProcAddress(g_dbgengModule, "DebugCreate");
        if (g_pfnDebugCreate) {
            g_usingWinDbgPreview = false;
            return true;
        }
        FreeLibrary(g_dbgengModule);
        g_dbgengModule = nullptr;
    }
    return false;
}

// Load WinDbg Preview's dbgeng.dll for TTD support
static bool loadWinDbgPreviewDbgEng() {
    // If we're already using WinDbg Preview, we're done
    if (g_usingWinDbgPreview && g_pfnDebugCreate) return true;
    
    // Known WinDbg Preview installation paths
    const char* windbgPaths[] = {
        "C:\\Program Files\\WindowsApps\\Microsoft.WinDbg_1.2601.12001.0_arm64__8wekyb3d8bbwe\\arm64",
        "C:\\Program Files\\WindowsApps\\Microsoft.WinDbg_1.2601.12001.0_x64__8wekyb3d8bbwe\\amd64",
    };
    
    for (const char* basePath : windbgPaths) {
        // Set DLL directory so dependencies can be found
        SetDllDirectoryA(basePath);
        
        std::string dbgengPath = std::string(basePath) + "\\dbgeng.dll";
        HMODULE hMod = LoadLibraryExA(dbgengPath.c_str(), NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (hMod) {
            PFN_DebugCreate pfn = (PFN_DebugCreate)GetProcAddress(hMod, "DebugCreate");
            if (pfn) {
                g_dbgengModule = hMod;
                g_pfnDebugCreate = pfn;
                g_usingWinDbgPreview = true;
                SetDllDirectoryA(NULL);
                return true;
            }
            FreeLibrary(hMod);
        }
        SetDllDirectoryA(NULL);
    }
    return false;
}

// Helper: format a value as a hex string ("0x1234ABCD").
static std::string toHex(uint64_t val) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << val;
    return oss.str();
}

namespace smalldbg {

// ---------------------------------------------------------------------------
// Simple output capture for Execute() commands
// ---------------------------------------------------------------------------
class DbgEngOutputCapture : public IDebugOutputCallbacks {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, PVOID* ppv) override {
        if (IsEqualIID(iid, __uuidof(IUnknown)) || IsEqualIID(iid, __uuidof(IDebugOutputCallbacks))) {
            *ppv = this;
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Output(ULONG /*mask*/, PCSTR text) override {
        if (text) captured_ += text;
        return S_OK;
    }
    void clear() { captured_.clear(); }
    const std::string& text() const { return captured_; }
private:
    std::string captured_;
};

// ---------------------------------------------------------------------------
// DbgEngEventCallbacks
// ---------------------------------------------------------------------------

ULONG STDMETHODCALLTYPE DbgEngEventCallbacks::AddRef()  { return 1; }
ULONG STDMETHODCALLTYPE DbgEngEventCallbacks::Release() { return 1; }

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::GetInterestMask(ULONG* mask) {
    *mask = DEBUG_EVENT_BREAKPOINT
          | DEBUG_EVENT_EXCEPTION
          | DEBUG_EVENT_CREATE_THREAD
          | DEBUG_EVENT_EXIT_THREAD
          | DEBUG_EVENT_CREATE_PROCESS
          | DEBUG_EVENT_EXIT_PROCESS
          | DEBUG_EVENT_LOAD_MODULE
          | DEBUG_EVENT_UNLOAD_MODULE;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::Breakpoint(IDebugBreakpoint* bp) {
    ULONG64 offset = 0;
    bp->GetOffset(&offset);
    backend->onBreakpoint(offset);
    return DEBUG_STATUS_BREAK;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::Exception(EXCEPTION_RECORD64* ex, ULONG firstChance) {
    DWORD code = ex->ExceptionCode;

    // Single step exception — always stop.
    if (code == static_cast<DWORD>(EXCEPTION_SINGLE_STEP)) {
        backend->onException(code, ex->ExceptionAddress);
        backend->setPendingExceptionContinue(0);
        return DEBUG_STATUS_BREAK;
    }

    // Breakpoint exception handling
    if (code == static_cast<DWORD>(EXCEPTION_BREAKPOINT)) {
        // In TTD mode: breakpoint exceptions are embedded trace events.
        // During stepping, returning BREAK would prevent the step from
        // completing.  Silently ignore them (don't set stopReason) and
        // return NO_CHANGE so the engine finishes the step operation.
        // This matches the bn-debugger approach where ALL callbacks
        // return NO_CHANGE.
        if (backend->isTTDTrace()) {
            // Explicitly tell the engine to continue execution past
            // the embedded break instruction in the TTD trace.
            return DEBUG_STATUS_GO;
        }
        backend->onException(code, ex->ExceptionAddress);
        backend->setPendingExceptionContinue(0);
        return DEBUG_STATUS_BREAK;
    }

    // All other exceptions: break so the event loop has control, and tell it
    // how to auto-continue (like WindowsBackend's ContinueDebugEvent).
    ULONG contStatus = firstChance
        ? DEBUG_STATUS_GO_NOT_HANDLED   // let SEH handle it
        : DEBUG_STATUS_GO;              // mark handled, avoid termination
    backend->setPendingExceptionContinue(contStatus);
    return DEBUG_STATUS_BREAK;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::CreateThread(ULONG64, ULONG64, ULONG64) {
    bool wantsBreak = backend->onThreadCreated();
    return wantsBreak ? DEBUG_STATUS_BREAK : DEBUG_STATUS_NO_CHANGE;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::ExitThread(ULONG) {
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::CreateProcess(
    ULONG64, ULONG64, ULONG64, ULONG, PCSTR, PCSTR imageName,
    ULONG, ULONG, ULONG64, ULONG64, ULONG64)
{
    backend->onProcessCreated(imageName ? imageName : "");
    return DEBUG_STATUS_BREAK;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::ExitProcess(ULONG exitCode) {
    backend->onProcessExit(exitCode);
    return DEBUG_STATUS_BREAK;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::LoadModule(
    ULONG64, ULONG64 baseOffset, ULONG moduleSize,
    PCSTR moduleName, PCSTR imageName, ULONG, ULONG)
{
    bool wantsBreak = backend->onModuleLoaded(baseOffset, moduleSize, moduleName, imageName);
    return wantsBreak ? DEBUG_STATUS_BREAK : DEBUG_STATUS_NO_CHANGE;
}

HRESULT STDMETHODCALLTYPE DbgEngEventCallbacks::UnloadModule(PCSTR imageName, ULONG64 baseOffset) {
    backend->onModuleUnloaded(baseOffset, imageName);
    return DEBUG_STATUS_NO_CHANGE;
}

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

DbgEngBackend::DbgEngBackend(Debugger* dbg, Mode m, const Arch* a)
    : Backend(dbg, m, a)
{
}

DbgEngBackend::~DbgEngBackend() {
    if (attached) {
        detach();
    }
    releaseInterfaces();
}

// ---------------------------------------------------------------------------
// COM interface helpers
// ---------------------------------------------------------------------------

bool DbgEngBackend::initInterfaces() {
    if (client) return true;

    // Ensure dbgeng.dll is loaded
    if (!ensureDbgEngLoaded()) {
        if (log) log("(dbgeng) failed to load dbgeng.dll");
        return false;
    }

    HRESULT hr = g_pfnDebugCreate(__uuidof(IDebugClient5), (void**)&client);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) DebugCreate failed, hr=" + toHex((unsigned long)hr));
        return false;
    }

    hr = client->QueryInterface(__uuidof(IDebugControl4),      (void**)&control);
    if (FAILED(hr)) { releaseInterfaces(); return false; }
    hr = client->QueryInterface(__uuidof(IDebugRegisters2),     (void**)&registers);
    if (FAILED(hr)) { releaseInterfaces(); return false; }
    hr = client->QueryInterface(__uuidof(IDebugDataSpaces4),    (void**)&dataSpaces);
    if (FAILED(hr)) { releaseInterfaces(); return false; }
    hr = client->QueryInterface(__uuidof(IDebugSymbols3),       (void**)&symbols);
    if (FAILED(hr)) { releaseInterfaces(); return false; }
    hr = client->QueryInterface(__uuidof(IDebugSystemObjects4), (void**)&sysObjects);
    if (FAILED(hr)) { releaseInterfaces(); return false; }
    hr = client->QueryInterface(__uuidof(IDebugAdvanced3),      (void**)&advanced);
    if (FAILED(hr)) { releaseInterfaces(); return false; }

    return true;
}

void DbgEngBackend::releaseInterfaces() {
    auto safeRelease = [](auto*& p) { if (p) { p->Release(); p = nullptr; } };
    safeRelease(advanced);
    safeRelease(sysObjects);
    safeRelease(symbols);
    safeRelease(dataSpaces);
    safeRelease(registers);
    safeRelease(control);
    safeRelease(client);
}

// ---------------------------------------------------------------------------
// attach / launch / detach
// ---------------------------------------------------------------------------

Status DbgEngBackend::attach(uintptr_t pid) {
    if (attached) return Status::AlreadyAttached;

    attachPid = pid;
    initMode = InitMode::Attach;
    initDone = false;
    initOk   = false;

    running = true;
    if (eventThread.joinable()) eventThread.join();
    eventThread = std::thread(&DbgEngBackend::eventLoop, this);

    // Wait for the event loop thread to finish initialisation.
    {
        std::unique_lock<std::mutex> lock(initMutex);
        initCv.wait(lock, [this]{ return initDone; });
    }

    if (!initOk) {
        running = false;
        if (eventThread.joinable()) eventThread.join();
        return Status::Error;
    }

    if (log) log("(dbgeng) attached to pid " + std::to_string(pid));
    return Status::Ok;
}

Status DbgEngBackend::launch(const std::string& path, const std::vector<std::string>& args) {
    if (attached) return Status::Error;

    launchPath = path;
    launchArgs = args;
    initMode = InitMode::Launch;
    initDone = false;
    initOk   = false;

    running = true;
    if (eventThread.joinable()) eventThread.join();
    eventThread = std::thread(&DbgEngBackend::eventLoop, this);

    {
        std::unique_lock<std::mutex> lock(initMutex);
        initCv.wait(lock, [this]{ return initDone; });
    }

    if (!initOk) {
        running = false;
        if (eventThread.joinable()) eventThread.join();
        return Status::Error;
    }

    if (log) log("(dbgeng) launched \"" + path + "\" pid=" + std::to_string(attachedPid().value_or(0)));
    return Status::Ok;
}

Status DbgEngBackend::detach() {
    if (!attached) return Status::NotAttached;

    running = false;
    // Break out of WaitForEvent(INFINITE) in pumpEvents
    if (control) control->SetInterrupt(DEBUG_INTERRUPT_EXIT);
    cv.notify_all();
    if (eventThread.joinable()) eventThread.join();

    if (client) {
        client->DetachProcesses();
        client->EndSession(DEBUG_END_PASSIVE);
    }

    attached = false;
    process.reset();
    releaseInterfaces();

    {
        std::lock_guard<std::mutex> g(bpMutex);
        breakpoints.clear();
    }

    if (log) log("(dbgeng) detached from pid " + std::to_string(attachedPid().value_or(0)));
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Run control — mirrors WindowsBackend::resume/step/suspend
// ---------------------------------------------------------------------------

Status DbgEngBackend::resume() {
    if (!attached) return Status::NotAttached;

    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!stopped) {
            if (log) log("(dbgeng) resume: already running");
            return Status::Ok;
        }

        stopped = false;
        stopReason = StopReason::None;
        stepRequested = false;
        pendingExecStatus = DEBUG_STATUS_GO;
        continueRequested = true;
    }
    cv.notify_all();

    if (log) log("(dbgeng) resume");
    return Status::Ok;
}

Status DbgEngBackend::step(Thread* thread) {
    if (!attached) return Status::NotAttached;

    {
        std::lock_guard<std::mutex> lock(mutex);
        stepRequested = true;
        stepThreadId = thread ? static_cast<DWORD>(thread->getThreadId()) : 0;
        stopped = false;
        stopReason = StopReason::None;
        pendingExecStatus = DEBUG_STATUS_STEP_INTO;
        continueRequested = true;
    }
    cv.notify_all();

    if (log) log("(dbgeng) step requested");
    return Status::Ok;
}

Status DbgEngBackend::suspend() {
    if (!attached) {
        if (log) log("(dbgeng) suspend: not attached");
        return Status::NotAttached;
    }

    {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopped) {
            if (log) log("(dbgeng) suspend: already stopped (reason="
                         + std::to_string((int)stopReason) + ")");
            return Status::Ok;
        }
    }

    HRESULT hr = control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
    if (FAILED(hr) && log)
        log("(dbgeng) suspend: SetInterrupt failed hr=" + toHex((unsigned long)hr));

    if (log) log("(dbgeng) suspend requested");
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// TTD (Time Travel Debugging)
// ---------------------------------------------------------------------------

Status DbgEngBackend::openTrace(const std::string& path) {
    if (attached) {
        if (log) log("(dbgeng) openTrace: already attached, detach first");
        return Status::Error;
    }

    if (log) log("(dbgeng) openTrace: opening " + path);

    // Load WinDbg Preview's dbgeng.dll which has built-in TTD support.
    // It opens .run traces via OpenDumpFile and loads the TTD engine from
    // a TTD/ subdirectory next to dbgeng.dll.  This gives us full DbgEng
    // support (symbols, stack traces, registers, memory, breakpoints,
    // reverse stepping) through standard COM APIs.
    if (!loadWinDbgPreviewDbgEng()) {
        if (log) log("(dbgeng) openTrace: failed to open trace");
        return Status::Error;
    }

    if (log) log("(dbgeng) openTrace: using WinDbg Preview dbgeng.dll via OpenDumpFile");

    // Launch the event loop which will do the actual OpenDumpFile + WaitForEvent
    tracePath = path;
    initMode = InitMode::OpenTrace;
    running = true;
    initDone = false;
    initOk = false;

    if (eventThread.joinable()) eventThread.join();
    eventThread = std::thread(&DbgEngBackend::eventLoop, this);

    // Wait for init to complete
    {
        std::unique_lock<std::mutex> lock(initMutex);
        initCv.wait(lock, [this]{ return initDone; });
    }

    if (!initOk) {
        // OpenDumpFile failed
        if (log) log("(dbgeng) openTrace: DbgEng OpenDumpFile failed");
        running = false;
        if (eventThread.joinable()) eventThread.join();
        return Status::Error;
    }

    isTTD = true;
    if (log) log("(dbgeng) TTD trace opened via DbgEng: " + tracePath);
    return Status::Ok;
}

Status DbgEngBackend::stepBack(Thread* thread) {
    if (!attached) return Status::NotAttached;
    if (!isTTD) {
        if (log) log("(dbgeng) stepBack: not a TTD trace");
        return Status::NotSupported;
    }

    // DbgEng-based reverse step
    if (thread && sysObjects) {
        ULONG engineId = 0;
        HRESULT hr = sysObjects->GetThreadIdBySystemId(
            static_cast<ULONG>(thread->getThreadId()), &engineId);
        if (SUCCEEDED(hr)) {
            sysObjects->SetCurrentThreadId(engineId);
        }
    }

    {
        std::lock_guard<std::mutex> g(mutex);
        stepRequested = true;
        stepThreadId = thread ? static_cast<DWORD>(thread->getThreadId()) : 0;
        pendingExecStatus = DEBUG_STATUS_REVERSE_STEP_INTO;
        continueRequested = true;
        stopped = false;
    }
    cv.notify_all();

    if (log) log("(dbgeng) stepBack requested");
    return Status::Ok;
}

Status DbgEngBackend::reverseResume() {
    if (!attached) return Status::NotAttached;
    if (!isTTD) {
        if (log) log("(dbgeng) reverseResume: not a TTD trace");
        return Status::NotSupported;
    }

    {
        std::lock_guard<std::mutex> g(mutex);
        stepRequested = false;
        pendingExecStatus = DEBUG_STATUS_REVERSE_GO;
        continueRequested = true;
        stopped = false;
    }
    cv.notify_all();

    if (log) log("(dbgeng) reverseResume requested");
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Breakpoints — DbgEng-managed
// ---------------------------------------------------------------------------

Status DbgEngBackend::setBreakpoint(Address addr, const std::string& name) {
    if (!attached) return Status::NotAttached;

    IDebugBreakpoint* bp = nullptr;
    HRESULT hr = control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
    if (FAILED(hr) || !bp) {
        if (log) log("(dbgeng) setBreakpoint: AddBreakpoint failed");
        return Status::Error;
    }

    bp->SetOffset(addr);
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);

    ULONG bpId = 0;
    bp->GetId(&bpId);

    {
        std::lock_guard<std::mutex> g(bpMutex);
        breakpoints.push_back({addr, name, bpId});
    }

    if (log) log("(dbgeng) breakpoint set at " + toHex(addr) + " id=" + std::to_string(bpId));
    return Status::Ok;
}

Status DbgEngBackend::clearBreakpoint(Address addr) {
    if (!attached) return Status::NotAttached;
    std::lock_guard<std::mutex> g(bpMutex);

    auto it = std::find_if(breakpoints.begin(), breakpoints.end(),
                           [addr](const BpInfo& b){ return b.addr == addr; });
    if (it == breakpoints.end()) return Status::NotFound;

    IDebugBreakpoint* bp = nullptr;
    HRESULT hr = control->GetBreakpointById(it->engineId, &bp);
    if (SUCCEEDED(hr) && bp) {
        control->RemoveBreakpoint(bp);
    }

    breakpoints.erase(it);
    if (log) log("(dbgeng) breakpoint cleared at " + toHex(addr));
    return Status::Ok;
}

std::vector<Breakpoint> DbgEngBackend::listBreakpoints() const {
    std::lock_guard<std::mutex> g(bpMutex);
    std::vector<Breakpoint> out;
    out.reserve(breakpoints.size());
    for (auto& b : breakpoints) {
        Breakpoint bp;
        bp.addr = b.addr;
        bp.enabled = true;
        bp.name = b.name;
        out.push_back(bp);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Memory access — IDebugDataSpaces4
// ---------------------------------------------------------------------------

Status DbgEngBackend::readMemory(Address address, void* outBuf, size_t size) const {
    if (!attached) return Status::NotAttached;

    ULONG bytesRead = 0;
    HRESULT hr = dataSpaces->ReadVirtual(address, outBuf, static_cast<ULONG>(size), &bytesRead);
    if (FAILED(hr) || bytesRead != size) return Status::NotFound;
    return Status::Ok;
}

Status DbgEngBackend::writeMemory(Address address, const void* data, size_t size) {
    if (!attached) return Status::NotAttached;
    if (!dataSpaces) return Status::NotSupported;

    ULONG bytesWritten = 0;
    HRESULT hr = dataSpaces->WriteVirtual(address, const_cast<void*>(data),
                                           static_cast<ULONG>(size), &bytesWritten);
    if (FAILED(hr) || bytesWritten != size) return Status::NotFound;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Register access — IDebugRegisters2
// ---------------------------------------------------------------------------

unsigned long DbgEngBackend::RegIndices::idx(const char* name) const {
    ULONG index = ~0u;
    regs->GetIndexByName(name, &index);
    return index;
}

uint64_t DbgEngBackend::RegIndices::readReg(unsigned long index) const {
    if (index == INVALID) return 0;
    DEBUG_VALUE val = {};
    HRESULT hr = regs->GetValue(index, &val);
    if (FAILED(hr)) return 0;
    return val.I64;
}

void DbgEngBackend::RegIndices::resolve(IDebugRegisters2* r) {
    if (ready) return;
    regs = r;

    // ARM64
    pc = idx("pc"); sp = idx("sp"); fp = idx("fp"); lr = idx("lr"); cpsr = idx("cpsr");
    for (int i = 0; i < 29; ++i) {
        char n[8];
        snprintf(n, sizeof(n), "x%d", i);
        x[i] = idx(n);
    }

    // x64
    rip = idx("rip"); rsp = idx("rsp"); rbp = idx("rbp"); rflags = idx("efl");
    rax = idx("rax"); rbx = idx("rbx"); rcx = idx("rcx"); rdx = idx("rdx");
    rsi = idx("rsi"); rdi = idx("rdi");
    r8  = idx("r8");  r9  = idx("r9");  r10 = idx("r10"); r11 = idx("r11");
    r12 = idx("r12"); r13 = idx("r13"); r14 = idx("r14"); r15 = idx("r15");

    // x86
    eip = idx("eip"); esp = idx("esp"); ebp = idx("ebp"); eflags = idx("efl");
    eax = idx("eax"); ebx = idx("ebx"); ecx = idx("ecx"); edx = idx("edx");
    esi = idx("esi"); edi = idx("edi");

    ready = true;
}

void DbgEngBackend::RegIndices::readX64Regs(X64Registers& r) const {
    r.rip    = readReg(rip);   r.rsp    = readReg(rsp);
    r.rbp    = readReg(rbp);   r.rflags = readReg(rflags);
    r.rax    = readReg(rax);   r.rbx    = readReg(rbx);
    r.rcx    = readReg(rcx);   r.rdx    = readReg(rdx);
    r.rsi    = readReg(rsi);   r.rdi    = readReg(rdi);
    r.r8     = readReg(r8);    r.r9     = readReg(r9);
    r.r10    = readReg(r10);   r.r11    = readReg(r11);
    r.r12    = readReg(r12);   r.r13    = readReg(r13);
    r.r14    = readReg(r14);   r.r15    = readReg(r15);
    r.pc     = r.rip;          r.sp     = r.rsp;
}

void DbgEngBackend::RegIndices::readX86Regs(X86Registers& r) const {
    r.eip    = static_cast<uint32_t>(readReg(eip));
    r.esp    = static_cast<uint32_t>(readReg(esp));
    r.ebp    = static_cast<uint32_t>(readReg(ebp));
    r.eflags = static_cast<uint32_t>(readReg(eflags));
    r.eax    = static_cast<uint32_t>(readReg(eax));
    r.ebx    = static_cast<uint32_t>(readReg(ebx));
    r.ecx    = static_cast<uint32_t>(readReg(ecx));
    r.edx    = static_cast<uint32_t>(readReg(edx));
    r.esi    = static_cast<uint32_t>(readReg(esi));
    r.edi    = static_cast<uint32_t>(readReg(edi));
}

void DbgEngBackend::RegIndices::readARM64Regs(ARM64Registers& r) const {
    r.pc     = readReg(pc);
    r.sp     = readReg(sp);
    r.x29_fp = readReg(fp);
    r.x30_lr = readReg(lr);
    for (int i = 0; i < 29; ++i)
        (&r.x0)[i] = readReg(x[i]);
}

Status DbgEngBackend::getRegisters(Thread* thread, Registers& out) const {
    if (!attached) return Status::NotAttached;

    // Switch engine context to the requested thread.
    if (thread) {
        DWORD tid = static_cast<DWORD>(thread->getThreadId());
        ULONG engineId = 0;
        HRESULT hr = sysObjects->GetThreadIdBySystemId(tid, &engineId);
        if (SUCCEEDED(hr)) {
            sysObjects->SetCurrentThreadId(engineId);
        } else if (log) {
            log("(dbgeng) getRegisters: thread " + std::to_string(tid)
                + " not found, hr=" + toHex((unsigned long)hr));
        }
    }

    if (!arch) {
        if (log) log("(dbgeng) getRegisters: no architecture detected");
        return Status::Error;
    }

    arch->readRegisters(ri, out);
    if (log) log("(dbgeng) getRegisters: ip=" + toHex(out.ip()) + " sp=" + toHex(out.sp()));
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Stack unwinding via DbgEng
// ---------------------------------------------------------------------------

Status DbgEngBackend::recoverCallerRegisters(Registers& regs) const {
    if (!attached) return Status::NotAttached;

    // Walk the frame pointer chain via memory reads.  This is more reliable
    // than GetStackTrace(ip,sp,fp,2) for continuation, because DbgEng's
    // GetStackTrace with explicit non-zero offsets doesn't properly support
    // iterative frame-by-frame unwinding (it needs the full thread context,
    // not just IP/SP/FP).
    //
    // Standard ARM64/x64 frame layout at FP:
    //   [FP + 0]         = caller's saved frame pointer
    //   [FP + ptrSize]   = return address (caller's continuation IP)

    Address fp = regs.fp();
    if (fp == 0) return Status::Error;

    size_t ptrSize = regs.pointerSize();
    Address callerFp = 0;
    Address callerIp = 0;

    if (readMemory(fp, &callerFp, ptrSize) != Status::Ok)
        return Status::Error;
    if (readMemory(fp + ptrSize, &callerIp, ptrSize) != Status::Ok)
        return Status::Error;

    // Validate: IP must be non-zero, FP must advance (stack grows down)
    // unless we've reached the stack base (callerFp == 0).
    if (callerIp == 0)
        return Status::Error;
    if (callerFp != 0 && callerFp <= fp)
        return Status::Error;

    regs.setIp(callerIp);
    regs.setFp(callerFp);
    regs.setSp(fp + 2 * ptrSize);  // approximate: SP at call site

    return Status::Ok;
}

// ---------------------------------------------------------------------------
// waitForEvent — same as WindowsBackend::waitForEvent
// ---------------------------------------------------------------------------

StopReason DbgEngBackend::waitForEvent(StopReason reason, int timeout_ms) {
    if (!attached) return StopReason::None;

    std::unique_lock<std::mutex> lock(mutex);

    auto pred = [this, reason]() {
        return stopped && (reason == StopReason::None || stopReason == reason);
    };

    if (timeout_ms == 0) {
        return pred() ? stopReason : StopReason::None;
    } else if (timeout_ms < 0) {
        cv.wait(lock, pred);
        return stopReason;
    } else {
        bool ok = cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred);
        return ok ? stopReason : StopReason::None;
    }
}

// ---------------------------------------------------------------------------
// Event loop — modelled on WindowsBackend::debugLoop()
//
// Structure:
//   Phase 1 — initSession() creates interfaces, launches/attaches, enumerates
//             threads, checks arch, registers symbol backend.
//   Phase 2 — Main loop:
//     a. waitForResumeSignal() — park until resume/step from user thread.
//     b. beginExecution()     — tell engine GO or STEP_INTO.
//     c. pumpEvents()         — pump WaitForEvent until interesting event.
// ---------------------------------------------------------------------------

void DbgEngBackend::eventLoop() {
    if (log) log("(dbgeng) event loop thread started");

    if (!initSession()) return;

    while (running) {
        if (!waitForResumeSignal()) break;

        ULONG execStatus = DEBUG_STATUS_GO;
        beginExecution(execStatus);
        pumpEvents(execStatus);
    }

    client->SetEventCallbacks(nullptr);
    running = false;
}

// ---------------------------------------------------------------------------
// Phase 1 — Session initialisation
// ---------------------------------------------------------------------------

bool DbgEngBackend::initSession() {
    auto signalInit = [this](bool ok) {
        std::lock_guard<std::mutex> lock(initMutex);
        initOk   = ok;
        initDone = true;
        initCv.notify_all();
    };

    if (!initInterfaces()) {
        if (log) log("(dbgeng) event loop: initInterfaces failed");
        signalInit(false);
        running = false;
        return false;
    }

    // Install event callbacks (stored as member so they live for the session).
    eventCallbacksImpl = std::make_unique<DbgEngEventCallbacks>(this);
    client->SetEventCallbacks(eventCallbacksImpl.get());

    bool ok = false;
    switch (initMode) {
    case InitMode::Launch:    ok = initLaunch();    break;
    case InitMode::Attach:    ok = initAttach();    break;
    case InitMode::OpenTrace: ok = initOpenTrace(); break;
    default:                  break;
    }

    if (!ok) {
        signalInit(false);
        running = false;
        return false;
    }

    enumerateInitialThreads();

    if (!initArchAndRegisters()) {
        signalInit(false);
        running = false;
        return false;
    }

    registerSymbolBackend();
    captureStopState();

    {
        std::lock_guard<std::mutex> lock(mutex);
        stopped = true;
    }
    cv.notify_all();

    signalInit(true);
    return true;
}

bool DbgEngBackend::initLaunch() {
    std::string cmdLine = launchPath;
    for (auto& a : launchArgs) { cmdLine += ' '; cmdLine += a; }

    // Set working directory to the exe's folder.
    std::string workDir;
    {
        size_t lastSlash = launchPath.find_last_of("\\/");
        if (lastSlash != std::string::npos)
            workDir = launchPath.substr(0, lastSlash);
    }
    char prevDir[MAX_PATH] = {};
    bool changedDir = false;
    if (!workDir.empty()) {
        GetCurrentDirectoryA(MAX_PATH, prevDir);
        changedDir = SetCurrentDirectoryA(workDir.c_str()) != 0;
        if (log) log("(dbgeng) set working dir to: " + workDir);
    }

    HRESULT hr = client->CreateProcess(
        0, const_cast<char*>(cmdLine.c_str()),
        DEBUG_ONLY_THIS_PROCESS | DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP);

    if (changedDir) SetCurrentDirectoryA(prevDir);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) CreateProcess failed hr=" + toHex((unsigned long)hr));
        return false;
    }

    hr = control->WaitForEvent(0, INFINITE);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) WaitForEvent (launch) failed");
        return false;
    }

    ULONG sysPid = 0;
    sysObjects->GetCurrentProcessSystemId(&sysPid);
    attached = true;
    initProcess(static_cast<uintptr_t>(sysPid));
    return true;
}

bool DbgEngBackend::initAttach() {
    HRESULT hr = client->AttachProcess(0, static_cast<ULONG>(attachPid),
                                        DEBUG_ATTACH_DEFAULT);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) AttachProcess failed hr=" + toHex((unsigned long)hr));
        return false;
    }

    hr = control->WaitForEvent(0, INFINITE);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) WaitForEvent (attach) failed");
        return false;
    }

    attached = true;
    initProcess(static_cast<uintptr_t>(attachPid));
    return true;
}

bool DbgEngBackend::initOpenTrace() {
    if (log) log("(dbgeng) OpenTrace: calling OpenDumpFile for " + tracePath);

    HRESULT hr = client->OpenDumpFile(tracePath.c_str());
    if (FAILED(hr)) {
        if (log) log("(dbgeng) OpenDumpFile failed hr=" + toHex((unsigned long)hr));
        return false;
    }

    hr = control->WaitForEvent(0, INFINITE);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) WaitForEvent (OpenDumpFile) failed hr=" + toHex((unsigned long)hr));
        return false;
    }

    if (log) log("(dbgeng) OpenTrace: dump opened, indexing TTD trace...");

    hr = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "!index", DEBUG_EXECUTE_DEFAULT);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) !index failed hr=" + toHex((unsigned long)hr) + " (non-fatal)");
    } else {
        if (log) log("(dbgeng) TTD trace indexed successfully");
    }

    ULONG sysPid = 0;
    if (sysObjects) sysObjects->GetCurrentProcessSystemId(&sysPid);
    attached = true;
    isTTD = true;
    initProcess(static_cast<uintptr_t>(sysPid));
    return true;
}

void DbgEngBackend::enumerateInitialThreads() {
    ULONG numThreads = 0;
    sysObjects->GetNumberThreads(&numThreads);
    std::vector<ULONG> ids(numThreads), sysIds(numThreads);
    if (numThreads > 0) {
        sysObjects->GetThreadIdsByIndex(0, numThreads, ids.data(), sysIds.data());
        for (ULONG i = 0; i < numThreads; ++i)
            process->registerThread(static_cast<ThreadId>(sysIds[i]));
    }
    if (log) log("(dbgeng) enumerated " + std::to_string(numThreads) + " threads");
}

bool DbgEngBackend::initArchAndRegisters() {
    ULONG actualType = 0;
    HRESULT hr = control->GetActualProcessorType(&actualType);
    if (FAILED(hr)) {
        if (log) log("(dbgeng) GetActualProcessorType failed hr=" + toHex((unsigned long)hr));
        return false;
    }

    const Arch* targetArch = nullptr;
    switch (actualType) {
    case IMAGE_FILE_MACHINE_I386:  targetArch = X86::instance();   break;
    case IMAGE_FILE_MACHINE_AMD64: targetArch = X64::instance();   break;
    case IMAGE_FILE_MACHINE_ARM64: targetArch = ARM64::instance(); break;
    default: break;
    }

    if (!targetArch) {
        if (log) log("(dbgeng) Unknown target machine type " + std::to_string(actualType));
        return false;
    }

    if (targetArch != arch) {
        if (log) {
            log("(dbgeng) Architecture mismatch: debugger is " + std::string(arch->name())
                + " but target is " + std::string(targetArch->name()));
            log("(dbgeng) Cross-architecture debugging is not supported.");
        }
        client->DetachProcesses();
        client->EndSession(DEBUG_END_PASSIVE);
        return false;
    }

    ri.resolve(registers);
    if (log) log("(dbgeng) architecture " + std::string(arch->name()) + ", register indices resolved");
    return true;
}

void DbgEngBackend::registerSymbolBackend() {
    auto* symProvider = debugger->getSymbolProvider();
    auto symBackend = std::make_unique<DbgEngSymbolBackend>(symbols, control);
    symBackend->initialize(nullptr, symProvider->getOptions());
    symProvider->addBackend(std::move(symBackend));
    if (log) log("(dbgeng) registered DbgEngSymbolBackend");
}

// ---------------------------------------------------------------------------
// Phase 2 — Main loop helpers
// ---------------------------------------------------------------------------

bool DbgEngBackend::waitForResumeSignal() {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [this]{ return continueRequested || !running.load(); });
    if (!running) return false;
    continueRequested = false;
    stopReason = StopReason::None;
    return true;
}

void DbgEngBackend::beginExecution(ULONG& execStatus) {
    DWORD stepTid = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        execStatus = pendingExecStatus ? pendingExecStatus : DEBUG_STATUS_GO;
        stepTid = stepThreadId;
        stepRequested = false;
        pendingExecStatus = 0;
    }

    // Remember PC before stepping (for TTD end-of-trace detection).
    bool isStep = (execStatus == DEBUG_STATUS_STEP_INTO ||
                   execStatus == DEBUG_STATUS_REVERSE_STEP_INTO);
    stepPending = isStep;
    if (isStep) {
        ULONG64 pcBefore = 0;
        registers->GetInstructionOffset(&pcBefore);
        lastStepPC = static_cast<Address>(pcBefore);
    }

    if (stepTid != 0) {
        ULONG engineId = 0;
        HRESULT hr = sysObjects->GetThreadIdBySystemId(stepTid, &engineId);
        if (SUCCEEDED(hr)) sysObjects->SetCurrentThreadId(engineId);
    }

    HRESULT hr = control->SetExecutionStatus(execStatus);
    if (FAILED(hr) && log)
        log("(dbgeng) SetExecutionStatus(" + std::to_string(execStatus) + ") failed");
}

void DbgEngBackend::pumpEvents(ULONG execStatus) {
    while (running) {
        HRESULT hr = control->WaitForEvent(0, INFINITE);

        if (hr == S_FALSE) continue;  // should not happen with INFINITE

        if (FAILED(hr)) {
            if (log) log("(dbgeng) event loop: WaitForEvent failed hr="
                         + toHex((unsigned long)hr));
            {
                std::lock_guard<std::mutex> lock(mutex);
                stopped = true;
                stopReason = StopReason::ProcessExit;
                stopAddress = 0;
            }
            cv.notify_all();
            running = false;
            return;
        }

        // Auto-continue pending exceptions (non-breakpoint, non-single-step).
        if (pendingContinueStatus != 0) {
            ULONG cs = pendingContinueStatus;
            pendingContinueStatus = 0;
            control->SetExecutionStatus(cs);
            continue;
        }

        ULONG64 pc = 0;
        registers->GetInstructionOffset(&pc);

        EventAction action = handleDebugEvent(execStatus, pc);

        switch (action) {
        case EventAction::Continue:
            control->SetExecutionStatus(DEBUG_STATUS_GO);
            continue;
        case EventAction::EndOfTrace:
        case EventAction::Stop:
            return;  // back to outer loop
        case EventAction::SessionEnded:
            running = false;
            return;
        }
    }
}

DbgEngBackend::EventAction
DbgEngBackend::handleDebugEvent(ULONG execStatus, ULONG64 pc) {
    {
        std::lock_guard<std::mutex> lock(mutex);
        stopAddress = static_cast<Address>(pc);
    }

    // TTD: forward step at same PC → end of trace.
    if (isTTD && execStatus == DEBUG_STATUS_STEP_INTO &&
        pc == static_cast<ULONG64>(lastStepPC)) {
        if (log) log("(dbgeng) TTD forward step at same PC — end of trace");
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopAddress = static_cast<Address>(pc);
            stopReason = StopReason::ProcessExit;
            stopped = true;
            stepPending = false;
        }
        cv.notify_all();
        return EventAction::EndOfTrace;
    }

    // Classify stop reason from engine state if not already set by callback.
    if (stopReason == StopReason::None) {
        captureStopState();
    }

    // Reclassify breakpoint-during-step as SingleStep.
    if (stepPending && stopReason == StopReason::Breakpoint) {
        std::lock_guard<std::mutex> lock(mutex);
        stopReason = StopReason::SingleStep;
    }

    if (log) {
        log("(dbgeng) event: reason=" + std::to_string((int)stopReason)
            + " pc=" + toHex(pc));
    }

    // Uninteresting event → auto-continue.
    if (stopReason == StopReason::None) {
        return EventAction::Continue;
    }

    // Set the current thread on the debugger.
    if (process) {
        ULONG sysId = 0;
        sysObjects->GetCurrentThreadSystemId(&sysId);
        auto threadOpt = process->getThread(static_cast<ThreadId>(sysId));
        if (threadOpt) {
            debugger->setCurrentThread(*threadOpt);
        }
    }

    // Invoke user event callback.
    if (eventCallback && eventCallback(stopReason, stopAddress)) {
        std::lock_guard<std::mutex> lock(mutex);
        stopReason = StopReason::None;
        return EventAction::Continue;
    }

    // Stopped — notify waiters.
    {
        std::lock_guard<std::mutex> lock(mutex);
        stopped = true;
        stepPending = false;
    }
    cv.notify_all();
    return EventAction::Stop;
}

// ---------------------------------------------------------------------------
// executeCommand — run a raw DbgEng command and return captured output.
// ---------------------------------------------------------------------------

std::string DbgEngBackend::executeCommand(const std::string& cmd) const {
    if (!control || !client) return "(no engine)";
    DbgEngOutputCapture cap;
    IDebugOutputCallbacks* oldCb = nullptr;
    const_cast<IDebugClient5*>(client)->GetOutputCallbacks(&oldCb);
    const_cast<IDebugClient5*>(client)->SetOutputCallbacks(&cap);
    const_cast<IDebugControl4*>(control)->Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd.c_str(),
                                                    DEBUG_EXECUTE_NO_REPEAT);
    const_cast<IDebugClient5*>(client)->SetOutputCallbacks(oldCb);
    return cap.text();
}

// ---------------------------------------------------------------------------
// captureStopState — fill stopReason from engine's last event information.
// ---------------------------------------------------------------------------

void DbgEngBackend::captureStopState() {
    ULONG64 pc = 0;
    registers->GetInstructionOffset(&pc);

    std::lock_guard<std::mutex> lock(mutex);
    stopAddress = static_cast<Address>(pc);

    // If a callback already set the reason, keep it.
    if (stopReason != StopReason::None) return;

    // Ask the engine what the last event was.
    ULONG eventType = 0;
    ULONG processId = 0, threadId = 0;
    char desc[256] = {};
    ULONG descUsed = 0;
    ULONG extraSize = 0;
    HRESULT hr = control->GetLastEventInformation(
        &eventType, &processId, &threadId,
        nullptr, 0, &extraSize,
        desc, sizeof(desc), &descUsed);

    if (SUCCEEDED(hr)) {
        switch (eventType) {
        case DEBUG_EVENT_BREAKPOINT:
            stopReason = StopReason::Breakpoint;
            break;
        case DEBUG_EVENT_EXCEPTION:
            // In TTD mode, breakpoint exceptions during steps are normal
            // trace events — treat step completion as SingleStep.
            if (isTTD && stepPending) {
                stopReason = StopReason::SingleStep;
            } else {
                // If a callback wanted to break it would have already set
                // stopReason.  Getting here means the exception was
                // internally handled — treat as "keep going".
                stopReason = StopReason::None;
            }
            break;
        case DEBUG_EVENT_CREATE_PROCESS:
            stopReason = StopReason::ProcessCreated;
            break;
        case DEBUG_EVENT_EXIT_PROCESS:
            stopReason = StopReason::ProcessExit;
            break;
        case DEBUG_EVENT_LOAD_MODULE:
            stopReason = StopReason::ModuleLoaded;
            break;
        case DEBUG_EVENT_UNLOAD_MODULE:
            stopReason = StopReason::ModuleUnloaded;
            break;
        case DEBUG_EVENT_CREATE_THREAD:
            stopReason = StopReason::ThreadCreated;
            break;
        default:
            stopReason = StopReason::Breakpoint;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Callbacks from DbgEngEventCallbacks
// These run on the event loop thread, inside WaitForEvent.
// ---------------------------------------------------------------------------

void DbgEngBackend::onBreakpoint(ULONG64 offset) {
    std::lock_guard<std::mutex> lock(mutex);

    bool isUser = false;
    {
        std::lock_guard<std::mutex> g(bpMutex);
        isUser = std::any_of(breakpoints.begin(), breakpoints.end(),
                             [offset](const BpInfo& b){ return b.addr == static_cast<Address>(offset); });
    }

    if (!seenInitialBreakpoint && !isUser) {
        seenInitialBreakpoint = true;
        stopReason = StopReason::InitialBreakpoint;
    } else {
        stopReason = StopReason::Breakpoint;
    }
    stopAddress = static_cast<Address>(offset);
    if (log) log("(dbgeng) BREAKPOINT at " + toHex(offset));
}

void DbgEngBackend::onException(DWORD code, ULONG64 address) {
    std::lock_guard<std::mutex> lock(mutex);
    if (code == static_cast<DWORD>(EXCEPTION_SINGLE_STEP)) {
        stopReason = StopReason::SingleStep;
    } else {
        stopReason = StopReason::Exception;
    }
    stopAddress = static_cast<Address>(address);
    if (log) log("(dbgeng) EXCEPTION code=" + toHex(code) + " at " + toHex(address));
}

bool DbgEngBackend::onThreadCreated() {
    ULONG sysId = 0;
    sysObjects->GetCurrentThreadSystemId(&sysId);
    if (process) process->registerThread(static_cast<ThreadId>(sysId));

    std::lock_guard<std::mutex> lock(mutex);
    stopReason = StopReason::ThreadCreated;
    if (log) log("(dbgeng) THREAD_CREATED tid=" + std::to_string(sysId));
    return false;  // never break for thread creation
}

void DbgEngBackend::onProcessCreated(const std::string& imageName) {
    std::lock_guard<std::mutex> lock(mutex);
    stopReason = StopReason::ProcessCreated;
    stopAddress = 0;
    if (log) log("(dbgeng) PROCESS_CREATED image=" + imageName);
}

void DbgEngBackend::onProcessExit(ULONG exitCode) {
    std::lock_guard<std::mutex> lock(mutex);
    stopReason = StopReason::ProcessExit;
    stopAddress = 0;
    attached = false;
    if (log) log("(dbgeng) PROCESS_EXIT code=" + std::to_string(exitCode));
}

bool DbgEngBackend::onModuleLoaded(ULONG64 base, ULONG size,
                                    const char* moduleName, const char* imageName) {
    // When an event callback is registered, return wantsBreak=true so that
    // WaitForEvent returns and handleDebugEvent can invoke the callback
    // (outside the engine callback, where symbol queries are safe).
    bool wantsBreak = (eventCallback != nullptr);

    {
        std::lock_guard<std::mutex> lock(mutex);
        stopReason = StopReason::ModuleLoaded;
    }

    if (log) {
        std::string msg = "(dbgeng) MODULE_LOADED base=" + toHex(base);
        if (imageName && imageName[0]) msg += " " + std::string(imageName);
        else if (moduleName && moduleName[0]) msg += " " + std::string(moduleName);
        log(msg);
    }
    return wantsBreak;
}

void DbgEngBackend::onModuleUnloaded(ULONG64 base, const char* imageName) {
    std::lock_guard<std::mutex> lock(mutex);
    stopReason = StopReason::ModuleUnloaded;
    if (log) {
        std::string msg = "(dbgeng) MODULE_UNLOADED base=" + toHex(base);
        if (imageName && imageName[0]) msg += " " + std::string(imageName);
        log(msg);
    }
}

} // namespace smalldbg
