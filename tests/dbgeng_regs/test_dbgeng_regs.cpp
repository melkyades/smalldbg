// DbgEng register-reading test harness.
//
// Launches test_dbgeng_target.exe under DbgEng, catches each int3
// breakpoint, and tries EVERY possible way to read registers:
//
//   x64 methods — test rax/rbx/rcx/rdx/rsi/rdi/r8/r9
//   x86 methods — test eax/ebx/ecx/edx/esi/edi
//
// Detects target architecture from PE header and runs appropriate tests.

#include <windows.h>
#include <dbgeng.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

#pragma comment(lib, "dbgeng.lib")

// --------------------------------------------------------------------------
// Detect PE architecture from file
// --------------------------------------------------------------------------
static WORD getPEMachineType(const char* exePath) {
    FILE* f = fopen(exePath, "rb");
    if (!f) return 0;

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, f) != 1 || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }

    // Seek to PE header
    fseek(f, dosHeader.e_lfanew, SEEK_SET);

    // Read PE signature + file header
    DWORD peSignature;
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&peSignature, sizeof(peSignature), 1, f) != 1 || peSignature != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }
    if (fread(&fileHeader, sizeof(fileHeader), 1, f) != 1) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return fileHeader.Machine;
}

// --------------------------------------------------------------------------
// Expected values for x64 targets (test_dbgeng_target built for x64)
// --------------------------------------------------------------------------
struct Expected {
    const char* name;
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, r8, r9;
};

static const Expected expected_x64[] = {
    { "small",
      0x0000000000000001, 0x0000000000000002, 0x0000000000000003,
      0x0000000000000004, 0x0000000000000005, 0x0000000000000006,
      0x0000000000000007, 0x0000000000000008 },
    { "large32",
      0x00000000AABBCCDD, 0x0000000011223344, 0x0000000055667788,
      0x0000000099AABBCC, 0x00000000DDEEFF00, 0x0000000012345678,
      0x00000000CAFEBABE, 0x00000000FEEDFACE },
    { "large64",
      0x123456789ABCDEF0, 0xFEDCBA9876543210, 0xAAAABBBBCCCCDDDD,
      0x1111222233334444, 0x5555666677778888, 0x9999AAAABBBBCCCC,
      0xDDDDEEEEFFFF0000, 0x0001000200030004 },
    { "deadbeef",
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
      0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF },
};
static const int numExpected_x64 = sizeof(expected_x64) / sizeof(expected_x64[0]);

// --------------------------------------------------------------------------
// Expected values for x86 targets (test_dbgeng_target built for x86)
// x86 only has eax/ebx/ecx/edx/esi/edi - we store them in rax..rdi fields
// --------------------------------------------------------------------------
static const Expected expected_x86[] = {
    { "small",
      0x00000001, 0x00000002, 0x00000003,
      0x00000004, 0x00000005, 0x00000006,
      0, 0 },  // no r8/r9 on x86
    { "large32",
      0xAABBCCDD, 0x11223344, 0x55667788,
      0x99AABBCC, 0xDDEEFF00, 0x12345678,
      0, 0 },
    { "deadbeef",
      0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF,
      0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF,
      0, 0 },
};
static const int numExpected_x86 = sizeof(expected_x86) / sizeof(expected_x86[0]);

// Runtime selection of expected values based on target architecture
static const Expected* g_expected = nullptr;
static int g_numExpected = 0;
static bool g_isX86Target = false;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
static std::string hex64(uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)v);
    return buf;
}

static std::string hex32(uint32_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%08X", v);
    return buf;
}

// Print result for x64 register set (rax, rbx, rcx, rdx, rsi, rdi, r8, r9)
static void printResult64(const char* method,
                          uint64_t rax, uint64_t rbx, uint64_t rcx,
                          uint64_t rdx, uint64_t rsi, uint64_t rdi,
                          uint64_t r8, uint64_t r9,
                          const Expected& exp)
{
    bool ok_rax = (rax == exp.rax);
    bool ok_rbx = (rbx == exp.rbx);
    bool ok_rcx = (rcx == exp.rcx);
    bool ok_rdx = (rdx == exp.rdx);
    bool ok_rsi = (rsi == exp.rsi);
    bool ok_rdi = (rdi == exp.rdi);
    bool ok_r8  = (r8  == exp.r8);
    bool ok_r9  = (r9  == exp.r9);
    bool allOk = ok_rax && ok_rbx && ok_rcx && ok_rdx && ok_rsi && ok_rdi && ok_r8 && ok_r9;

    printf("  %-12s %s\n", method, allOk ? "PASS" : "FAIL");
    printf("    rax=%s%s  rbx=%s%s\n",
           hex64(rax).c_str(), ok_rax ? "" : "!",
           hex64(rbx).c_str(), ok_rbx ? "" : "!");
    printf("    rcx=%s%s  rdx=%s%s\n",
           hex64(rcx).c_str(), ok_rcx ? "" : "!",
           hex64(rdx).c_str(), ok_rdx ? "" : "!");
    printf("    rsi=%s%s  rdi=%s%s\n",
           hex64(rsi).c_str(), ok_rsi ? "" : "!",
           hex64(rdi).c_str(), ok_rdi ? "" : "!");
    printf("    r8 =%s%s  r9 =%s%s\n",
           hex64(r8).c_str(),  ok_r8  ? "" : "!",
           hex64(r9).c_str(),  ok_r9  ? "" : "!");
}

// Print result for x86 register set (eax, ebx, ecx, edx, esi, edi) - compare lower 32 bits
static void printResult32(const char* method,
                          uint64_t eax, uint64_t ebx, uint64_t ecx,
                          uint64_t edx, uint64_t esi, uint64_t edi,
                          const Expected& exp)
{
    // Compare only lower 32 bits against expected lower 32 bits
    bool ok_eax = (static_cast<uint32_t>(eax) == static_cast<uint32_t>(exp.rax));
    bool ok_ebx = (static_cast<uint32_t>(ebx) == static_cast<uint32_t>(exp.rbx));
    bool ok_ecx = (static_cast<uint32_t>(ecx) == static_cast<uint32_t>(exp.rcx));
    bool ok_edx = (static_cast<uint32_t>(edx) == static_cast<uint32_t>(exp.rdx));
    bool ok_esi = (static_cast<uint32_t>(esi) == static_cast<uint32_t>(exp.rsi));
    bool ok_edi = (static_cast<uint32_t>(edi) == static_cast<uint32_t>(exp.rdi));
    bool allOk = ok_eax && ok_ebx && ok_ecx && ok_edx && ok_esi && ok_edi;

    printf("  %-12s %s\n", method, allOk ? "PASS" : "FAIL");
    printf("    eax=%s%s  ebx=%s%s  ecx=%s%s\n",
           hex32(static_cast<uint32_t>(eax)).c_str(), ok_eax ? "" : "!",
           hex32(static_cast<uint32_t>(ebx)).c_str(), ok_ebx ? "" : "!",
           hex32(static_cast<uint32_t>(ecx)).c_str(), ok_ecx ? "" : "!");
    printf("    edx=%s%s  esi=%s%s  edi=%s%s\n",
           hex32(static_cast<uint32_t>(edx)).c_str(), ok_edx ? "" : "!",
           hex32(static_cast<uint32_t>(esi)).c_str(), ok_esi ? "" : "!",
           hex32(static_cast<uint32_t>(edi)).c_str(), ok_edi ? "" : "!");
}

// --------------------------------------------------------------------------
// Event callback — just records stop reason
// --------------------------------------------------------------------------
enum StopKind { STOP_NONE, STOP_BP, STOP_INITIAL_BP, STOP_EXIT };
static StopKind g_lastStop = STOP_NONE;
static int g_bpCount = 0;
static IDebugControl4* g_control = nullptr;  // For stack trace in exception handler

class EventCB : public DebugBaseEventCallbacks {
public:
    STDMETHOD_(ULONG, AddRef)()  override { return 1; }
    STDMETHOD_(ULONG, Release)() override { return 1; }

    STDMETHOD(GetInterestMask)(PULONG mask) override {
        *mask = DEBUG_EVENT_BREAKPOINT | DEBUG_EVENT_EXCEPTION
              | DEBUG_EVENT_CREATE_PROCESS | DEBUG_EVENT_EXIT_PROCESS
              | DEBUG_EVENT_CREATE_THREAD | DEBUG_EVENT_LOAD_MODULE
              | DEBUG_EVENT_UNLOAD_MODULE;
        return S_OK;
    }

    STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT) override {
        g_lastStop = STOP_BP;
        return DEBUG_STATUS_BREAK;
    }

    STDMETHOD(Exception)(PEXCEPTION_RECORD64 ex, ULONG firstChance) override {
        // Print exception address as 32-bit for x86 targets
        if (g_isX86Target) {
            printf("  [EVENT] Exception 0x%08lX at 0x%08lX (firstChance=%lu)\n",
                   (unsigned long)ex->ExceptionCode, (unsigned long)(ex->ExceptionAddress & 0xFFFFFFFF), (unsigned long)firstChance);
        } else {
            printf("  [EVENT] Exception 0x%08lX at 0x%016llX (firstChance=%lu)\n",
                   (unsigned long)ex->ExceptionCode, (unsigned long long)ex->ExceptionAddress, (unsigned long)firstChance);
        }
        
        // STATUS_WX86_BREAKPOINT = 0x4000001F: WoW64/XTAJIT breakpoint for x86 on ARM64
        if (ex->ExceptionCode == static_cast<DWORD>(EXCEPTION_BREAKPOINT) ||
            ex->ExceptionCode == 0x4000001F) {
            g_bpCount++;
            g_lastStop = STOP_BP;
            return DEBUG_STATUS_BREAK;
        }
        if (ex->ExceptionCode == static_cast<DWORD>(EXCEPTION_SINGLE_STEP)) {
            return DEBUG_STATUS_BREAK;
        }
        // 0xC0000409 = STATUS_STACK_BUFFER_OVERRUN (fail-fast) - treat as fatal
        if (ex->ExceptionCode == 0xC0000409) {
            printf("  [FATAL] STATUS_STACK_BUFFER_OVERRUN - stopping\n");
            g_lastStop = STOP_EXIT;
            return DEBUG_STATUS_BREAK;
        }
        // Continue other first-chance exceptions, break on second-chance
        if (!firstChance) {
            printf("  [FATAL] Unhandled exception (second chance) - stopping\n");
            g_lastStop = STOP_EXIT;
            return DEBUG_STATUS_BREAK;
        }
        return DEBUG_STATUS_GO_NOT_HANDLED;
    }

    STDMETHOD(ExitProcess)(ULONG exitCode) override {
        printf("  [EVENT] ExitProcess (code=%lu)\n", (unsigned long)exitCode);
        g_lastStop = STOP_EXIT;
        return DEBUG_STATUS_BREAK;
    }

    STDMETHOD(CreateProcess)(ULONG64, ULONG64, ULONG64, ULONG, PCSTR, PCSTR,
                             ULONG, ULONG, ULONG64, ULONG64, ULONG64) override {
        return DEBUG_STATUS_BREAK;
    }

    STDMETHOD(CreateThread)(ULONG64, ULONG64, ULONG64) override {
        return DEBUG_STATUS_GO;
    }

    STDMETHOD(LoadModule)(ULONG64, ULONG64, ULONG, PCSTR, PCSTR, ULONG, ULONG) override {
        return DEBUG_STATUS_GO;
    }

    STDMETHOD(UnloadModule)(PCSTR, ULONG64) override {
        return DEBUG_STATUS_GO;
    }
};

// --------------------------------------------------------------------------
// Method A: IDebugRegisters2::GetValue — default effective processor (x64 names)
// --------------------------------------------------------------------------
static void methodA_x64(IDebugRegisters2* regs, const Expected& exp) {
    auto rv = [&](const char* name) -> uint64_t {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) return 0xBAD0BAD0BAD0BAD0ULL;
        DEBUG_VALUE val = {};
        if (FAILED(regs->GetValue(idx, &val))) return 0xBAD1BAD1BAD1BAD1ULL;
        return val.I64;
    };
    printResult64("A:x64+GV", rv("rax"), rv("rbx"), rv("rcx"),
                  rv("rdx"), rv("rsi"), rv("rdi"), rv("r8"), rv("r9"), exp);
}

static void methodA_x86(IDebugRegisters2* regs, const Expected& exp) {
    auto rv = [&](const char* name) -> uint64_t {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) return 0xBAD0BAD0ULL;
        DEBUG_VALUE val = {};
        if (FAILED(regs->GetValue(idx, &val))) return 0xBAD1BAD1ULL;
        return val.I64;
    };
    printResult32("A:x86+GV", rv("eax"), rv("ebx"), rv("ecx"),
                  rv("edx"), rv("esi"), rv("edi"), exp);
}

// --------------------------------------------------------------------------
// Method B: GetValue after SetEffectiveProcessorType(I386) — x86 names only
// --------------------------------------------------------------------------
static void methodB_x86(IDebugControl4* ctrl, IDebugRegisters2* regs, const Expected& exp) {
    ctrl->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
    auto rv = [&](const char* name) -> uint64_t {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) return 0xBAD0BAD0ULL;
        DEBUG_VALUE val = {};
        if (FAILED(regs->GetValue(idx, &val))) return 0xBAD1BAD1ULL;
        return val.I64;
    };
    // x86 mode: only test eax/ebx/ecx/edx/esi/edi (no r8/r9)
    printResult32("B:I386+GV", rv("eax"), rv("ebx"), rv("ecx"),
                  rv("edx"), rv("esi"), rv("edi"), exp);
}

// --------------------------------------------------------------------------
// Method C: GetValue after SetEffectiveProcessorType(AMD64) — x64 names
// --------------------------------------------------------------------------
static void methodC_x64(IDebugControl4* ctrl, IDebugRegisters2* regs, const Expected& exp) {
    ctrl->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64);
    auto rv = [&](const char* name) -> uint64_t {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) return 0xBAD0BAD0BAD0BAD0ULL;
        DEBUG_VALUE val = {};
        if (FAILED(regs->GetValue(idx, &val))) return 0xBAD1BAD1BAD1BAD1ULL;
        return val.I64;
    };
    printResult64("C:AMD64+GV", rv("rax"), rv("rbx"), rv("rcx"),
                  rv("rdx"), rv("rsi"), rv("rdi"), rv("r8"), rv("r9"), exp);
}

// --------------------------------------------------------------------------
// Method D: GetThreadContext with CONTEXT (x64), default effective processor
// --------------------------------------------------------------------------
#ifdef _M_AMD64
static void methodD_x64(IDebugAdvanced3* adv, const Expected& exp) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    HRESULT hr = adv->GetThreadContext(&ctx, sizeof(ctx));
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetThreadContext(x64) failed hr=0x%08lX)\n", "D:x64Ctx", (unsigned long)hr);
        return;
    }
    printResult64("D:x64Ctx",
                  ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, exp);
}
#endif

// --------------------------------------------------------------------------
// Method E: SetEffective(I386) + GetThreadContext with WOW64_CONTEXT
// (This method is designed for WOW64 x86 on x64, and ARM64 debugging x86)
// --------------------------------------------------------------------------
#if defined(_M_AMD64) || defined(_M_ARM64)
static void methodE_x86(IDebugControl4* ctrl, IDebugAdvanced3* adv, const Expected& exp) {
    ctrl->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;
    HRESULT hr = adv->GetThreadContext(&ctx, sizeof(ctx));
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetThreadContext(WOW64) failed hr=0x%08lX)\n", "E:WOW64Ctx", (unsigned long)hr);
        return;
    }
    // WOW64_CONTEXT only has 32-bit registers
    printResult32("E:WOW64Ctx",
                  ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, exp);
}
#endif

// --------------------------------------------------------------------------
// Method H: Use Win32 Wow64GetThreadContext directly with thread handle from DbgEng
// (This bypasses DbgEng's context translation entirely)
// --------------------------------------------------------------------------
#if defined(_M_ARM64)
static void methodH_wow64_direct(IDebugSystemObjects4* sysObj, const Expected& exp) {
    ULONG64 threadHandle = 0;
    HRESULT hr = sysObj->GetCurrentThreadHandle(&threadHandle);
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetCurrentThreadHandle failed hr=0x%08lX)\n", "H:Wow64Dir", (unsigned long)hr);
        return;
    }

    HANDLE hThread = (HANDLE)threadHandle;
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;
    
    if (!Wow64GetThreadContext(hThread, &ctx)) {
        DWORD err = GetLastError();
        printf("  %-12s SKIP (Wow64GetThreadContext failed err=%lu)\n", "H:Wow64Dir", (unsigned long)err);
        return;
    }
    
    printf("  %-12s eip=0x%08lX (x86 IP)\n", "H:Wow64Dir", (unsigned long)ctx.Eip);
    printResult32("H:Wow64Dir",
                  ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, exp);
}

// Method I: Try using NtQueryInformationThread with ThreadWow64Context
// On ARM64, the XTAJIT emulator stores x86 context separately
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static void methodI_ntquery(IDebugSystemObjects4* sysObj, const Expected& exp) {
    ULONG64 threadHandle = 0;
    HRESULT hr = sysObj->GetCurrentThreadHandle(&threadHandle);
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetCurrentThreadHandle failed hr=0x%08lX)\n", "I:NtQuery", (unsigned long)hr);
        return;
    }

    // ThreadWow64Context = 29
    static PFN_NtQueryInformationThread pNtQueryInformationThread = nullptr;
    if (!pNtQueryInformationThread) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        pNtQueryInformationThread = (PFN_NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
    }
    if (!pNtQueryInformationThread) {
        printf("  %-12s SKIP (NtQueryInformationThread not found)\n", "I:NtQuery");
        return;
    }

    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;
    ULONG returnLength = 0;
    NTSTATUS status = pNtQueryInformationThread((HANDLE)threadHandle, 29, &ctx, sizeof(ctx), &returnLength);
    if (status != 0) {
        printf("  %-12s SKIP (NtQueryInformationThread(29) status=0x%08lX)\n", "I:NtQuery", (unsigned long)status);
        return;
    }
    
    printf("  %-12s eip=0x%08lX (x86 IP)\n", "I:NtQuery", (unsigned long)ctx.Eip);
    printResult32("I:NtQuery",
                  ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, exp);
}

// Method J: Try with explicit SuspendThread/ResumeThread to force context sync
static void methodJ_suspend_resume(IDebugSystemObjects4* sysObj, const Expected& exp) {
    ULONG64 threadHandle = 0;
    HRESULT hr = sysObj->GetCurrentThreadHandle(&threadHandle);
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetCurrentThreadHandle failed hr=0x%08lX)\n", "J:SusRes", (unsigned long)hr);
        return;
    }

    HANDLE hThread = (HANDLE)threadHandle;
    
    // Try suspend/resume to force context flush
    // Note: Thread should already be suspended by debugger
    
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;
    
    // Call SuspendThread to increment suspend count, then get context
    SuspendThread(hThread);
    BOOL ok = Wow64GetThreadContext(hThread, &ctx);
    ResumeThread(hThread);  // Decrement back
    
    if (!ok) {
        DWORD err = GetLastError();
        printf("  %-12s SKIP (Wow64GetThreadContext after suspend failed err=%lu)\n", "J:SusRes", (unsigned long)err);
        return;
    }
    
    printf("  %-12s eip=0x%08lX (x86 IP)\n", "J:SusRes", (unsigned long)ctx.Eip);
    printResult32("J:SusRes",
                  ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, exp);
}
#endif

#ifdef _M_IX86
// Native x86 build - use native CONTEXT with Eax, Ebx, etc.
static void methodD_x86_native(IDebugAdvanced3* adv, const Expected& exp) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    HRESULT hr = adv->GetThreadContext(&ctx, sizeof(ctx));
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetThreadContext(x86) failed hr=0x%08lX)\n", "D:x86Ctx", (unsigned long)hr);
        return;
    }
    printResult32("D:x86Ctx",
                  ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, exp);
}
#endif

// --------------------------------------------------------------------------
// Method F: GetInstructionOffset / GetStackOffset / GetFrameOffset
// --------------------------------------------------------------------------
static void methodF(IDebugRegisters2* regs) {
    ULONG64 ip = 0, sp = 0, fp = 0;
    regs->GetInstructionOffset(&ip);
    regs->GetStackOffset(&sp);
    regs->GetFrameOffset(&fp);
    printf("  %-12s IP=%s  SP=%s  FP=%s\n", "F:Offsets",
           hex64(ip).c_str(), hex64(sp).c_str(), hex64(fp).c_str());
}

// --------------------------------------------------------------------------
// Method G: SetEffective(AMD64) + GetThreadContext with CONTEXT (x64)
// --------------------------------------------------------------------------
#ifdef _M_AMD64
static void methodG_x64(IDebugControl4* ctrl, IDebugAdvanced3* adv, const Expected& exp) {
    ctrl->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64);
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    HRESULT hr = adv->GetThreadContext(&ctx, sizeof(ctx));
    if (FAILED(hr)) {
        printf("  %-12s SKIP (GetThreadContext(AMD64) failed hr=0x%08lX)\n", "G:Amd64Ctx", (unsigned long)hr);
        return;
    }
    printResult64("G:Amd64Ctx",
                  ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, exp);
}
#endif

// --------------------------------------------------------------------------
// Run methods appropriate for the target architecture
// --------------------------------------------------------------------------
static void testAllMethods(IDebugControl4* ctrl, IDebugRegisters2* regs,
                           IDebugAdvanced3* adv, IDebugSystemObjects4* sysObj, const Expected& exp)
{
    // Save original effective processor type and restore after each test
    ULONG origType = 0;
    ctrl->GetEffectiveProcessorType(&origType);

    printf("\n--- Test point: %s ---\n", exp.name);

    if (g_isX86Target) {
        // x86 target - only show/test 32-bit registers
        printf("  Expected (32-bit):\n");
        printf("    eax=%s  ebx=%s  ecx=%s\n",
               hex32(static_cast<uint32_t>(exp.rax)).c_str(),
               hex32(static_cast<uint32_t>(exp.rbx)).c_str(),
               hex32(static_cast<uint32_t>(exp.rcx)).c_str());
        printf("    edx=%s  esi=%s  edi=%s\n",
               hex32(static_cast<uint32_t>(exp.rdx)).c_str(),
               hex32(static_cast<uint32_t>(exp.rsi)).c_str(),
               hex32(static_cast<uint32_t>(exp.rdi)).c_str());

        // x86 methods only
        printf("  -- x86 methods --\n");
        methodA_x86(regs, exp);
        ctrl->SetEffectiveProcessorType(origType);

        methodB_x86(ctrl, regs, exp);
        ctrl->SetEffectiveProcessorType(origType);

#ifdef _M_AMD64
        // WOW64_CONTEXT only available in x64 harness
        methodE_x86(ctrl, adv, exp);
        ctrl->SetEffectiveProcessorType(origType);
#elif defined(_M_IX86)
        // Native x86 harness - use native CONTEXT
        methodD_x86_native(adv, exp);
        ctrl->SetEffectiveProcessorType(origType);
#elif defined(_M_ARM64)
        // ARM64 harness - try WOW64_CONTEXT for x86 target
        methodE_x86(ctrl, adv, exp);
        ctrl->SetEffectiveProcessorType(origType);
        
        // Also try direct Wow64GetThreadContext API
        methodH_wow64_direct(sysObj, exp);
        
        // Also try NtQueryInformationThread with ThreadWow64Context
        methodI_ntquery(sysObj, exp);
        
        // Try with suspend/resume to force context sync
        methodJ_suspend_resume(sysObj, exp);
#endif
    } else {
        // x64 target - show/test full 64-bit registers
        printf("  Expected (64-bit):\n");
        printf("    rax=%s  rbx=%s\n", hex64(exp.rax).c_str(), hex64(exp.rbx).c_str());
        printf("    rcx=%s  rdx=%s\n", hex64(exp.rcx).c_str(), hex64(exp.rdx).c_str());
        printf("    rsi=%s  rdi=%s\n", hex64(exp.rsi).c_str(), hex64(exp.rdi).c_str());
        printf("    r8 =%s  r9 =%s\n", hex64(exp.r8).c_str(),  hex64(exp.r9).c_str());

#ifdef _M_AMD64
        // x64 methods only available in x64 harness
        printf("  -- x64 methods --\n");
        methodA_x64(regs, exp);
        ctrl->SetEffectiveProcessorType(origType);

        methodC_x64(ctrl, regs, exp);
        ctrl->SetEffectiveProcessorType(origType);

        methodD_x64(adv, exp);
        ctrl->SetEffectiveProcessorType(origType);

        methodG_x64(ctrl, adv, exp);
        ctrl->SetEffectiveProcessorType(origType);
#else
        printf("  (Cannot test x64 targets from non-x64 harness)\\n");
#endif
    }

    // Offsets (architecture-agnostic)
    printf("  -- Offsets --\n");
    methodF(regs);
    ctrl->SetEffectiveProcessorType(origType);
}

// ==========================================================================
// main
// ==========================================================================
int main(int argc, char** argv) {
    printf("=== DbgEng Register Reading Test ===\n\n");

    // Find the target exe (same directory as this exe)
    std::string targetPath;
    {
        char self[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, self, MAX_PATH);
        std::string selfStr(self);
        auto pos = selfStr.find_last_of("\\/");
        if (pos != std::string::npos)
            targetPath = selfStr.substr(0, pos + 1);
        targetPath += "test_dbgeng_target.exe";
    }

    // Allow override from command line
    if (argc > 1) targetPath = argv[1];

    printf("Target: %s\n", targetPath.c_str());

    // Detect target architecture from PE header
    WORD targetMachine = getPEMachineType(targetPath.c_str());
    printf("Target PE machine type: 0x%04X", targetMachine);
    switch (targetMachine) {
        case IMAGE_FILE_MACHINE_AMD64: printf(" (x64/AMD64)"); break;
        case IMAGE_FILE_MACHINE_I386:  printf(" (x86/I386)"); break;
        case 0xAA64:                   printf(" (ARM64)"); break;
        default: break;
    }
    printf("\n");

    // Set up expected values based on target architecture
    if (targetMachine == IMAGE_FILE_MACHINE_I386) {
        g_isX86Target = true;
        g_expected = expected_x86;
        g_numExpected = numExpected_x86;
        printf("Using x86 test points (%d tests)\n", g_numExpected);
    } else {
        g_isX86Target = false;
        g_expected = expected_x64;
        g_numExpected = numExpected_x64;
        printf("Using x64 test points (%d tests)\n", g_numExpected);
    }

    // Print host architecture info
    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    printf("Host native arch: 0x%04X", si.wProcessorArchitecture);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: printf(" (AMD64)"); break;
        case PROCESSOR_ARCHITECTURE_INTEL: printf(" (x86)"); break;
        case 12: printf(" (ARM64)"); break;
        default: break;
    }
    printf("\n");

    // Create DbgEng interfaces
    IDebugClient5*       client   = nullptr;
    IDebugControl4*      control  = nullptr;
    IDebugRegisters2*    regs     = nullptr;
    IDebugAdvanced3*     advanced = nullptr;
    IDebugSystemObjects4* sysObj  = nullptr;

    HRESULT hr = DebugCreate(__uuidof(IDebugClient5), (void**)&client);
    if (FAILED(hr)) { printf("DebugCreate failed: 0x%08lX\n", (unsigned long)hr); return 1; }

    client->QueryInterface(__uuidof(IDebugControl4),      (void**)&control);
    client->QueryInterface(__uuidof(IDebugRegisters2),    (void**)&regs);
    client->QueryInterface(__uuidof(IDebugAdvanced3),     (void**)&advanced);
    client->QueryInterface(__uuidof(IDebugSystemObjects4),(void**)&sysObj);

    // Set global for exception handler stack trace
    g_control = control;

    // Install event callbacks
    static EventCB ecb;
    client->SetEventCallbacks(&ecb);

    // Launch target
    hr = client->CreateProcess(0, const_cast<char*>(targetPath.c_str()),
                               DEBUG_ONLY_THIS_PROCESS | DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP);
    if (FAILED(hr)) {
        printf("CreateProcess failed: 0x%08lX\n", (unsigned long)hr);
        return 1;
    }

    // Wait for initial event (CREATE_PROCESS)
    hr = control->WaitForEvent(0, 5000);
    if (FAILED(hr)) {
        printf("WaitForEvent (initial) failed: 0x%08lX\n", (unsigned long)hr);
        return 1;
    }

    // Print processor types (before setting)
    ULONG actual = 0, effective = 0;
    control->GetActualProcessorType(&actual);
    control->GetEffectiveProcessorType(&effective);
    printf("Actual processor type: 0x%04lX", actual);
    if (actual == IMAGE_FILE_MACHINE_I386)  printf(" (I386)");
    if (actual == IMAGE_FILE_MACHINE_AMD64) printf(" (AMD64)");
    if (actual == 0xAA64)                   printf(" (ARM64)");
    printf("\n");
    printf("Effective processor type (before): 0x%04lX", effective);
    if (effective == IMAGE_FILE_MACHINE_I386)  printf(" (I386)");
    if (effective == IMAGE_FILE_MACHINE_AMD64) printf(" (AMD64)");
    if (effective == 0xAA64)                   printf(" (ARM64)");
    printf("\n");

    // For x86 targets, explicitly set effective processor type to I386
    // This is required on ARM64 Windows where x86 runs under XTAJIT emulation
    if (g_isX86Target) {
        printf("Setting effective processor type to I386 for x86 target...\n");
        HRESULT hr2 = control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
        if (FAILED(hr2)) {
            printf("  SetEffectiveProcessorType(I386) failed: 0x%08lX\n", (unsigned long)hr2);
        } else {
            control->GetEffectiveProcessorType(&effective);
            printf("Effective processor type (after): 0x%04lX", effective);
            if (effective == IMAGE_FILE_MACHINE_I386)  printf(" (I386)");
            if (effective == IMAGE_FILE_MACHINE_AMD64) printf(" (AMD64)");
            if (effective == 0xAA64)                   printf(" (ARM64)");
            printf("\n");
        }
    }

    // Enumerate registers with default effective type
    {
        ULONG numRegs = 0;
        regs->GetNumberRegisters(&numRegs);
        printf("Number of registers (default effective): %lu\n", numRegs);
        printf("First 20 registers:\n");
        for (ULONG i = 0; i < numRegs && i < 20; ++i) {
            char name[64] = {};
            DEBUG_REGISTER_DESCRIPTION desc = {};
            regs->GetDescription(i, name, sizeof(name), nullptr, &desc);
            printf("  [%2lu] %s (type=%lu)\n", i, name, desc.Type);
        }
    }

    // Resume past initial breakpoint, then catch each test point
    printf("\nResuming past initial breakpoint...\n");

    int testIndex = 0;

    while (testIndex < g_numExpected) {
        // Resume
        control->SetExecutionStatus(DEBUG_STATUS_GO);

        // Wait for next event
        hr = control->WaitForEvent(0, 10000);
        if (FAILED(hr)) {
            printf("WaitForEvent failed: 0x%08lX (session may have ended)\n", (unsigned long)hr);
            break;
        }

        if (g_lastStop == STOP_EXIT) {
            printf("Process exited.\n");
            break;
        }

        if (g_lastStop == STOP_BP) {
            // This should be one of our test-point int3s
            if (testIndex < g_numExpected) {
                testAllMethods(control, regs, advanced, sysObj, g_expected[testIndex]);
                testIndex++;
            }
        }
    }

    // Print summary
    printf("\n=== Summary ===\n");
    printf("Test points hit: %d / %d\n", testIndex, g_numExpected);
    printf("Look for PASS/FAIL above to see which method works.\n");

    // Cleanup
    client->DetachProcesses();
    client->EndSession(DEBUG_END_PASSIVE);
    advanced->Release();
    sysObj->Release();
    regs->Release();
    control->Release();
    client->Release();

    return 0;
}
