// C API (C-ABI) bindings for SmallDBG — generic C-style wrappers for foreign runtimes
#pragma once

#include "../Debugger.h"

extern "C" {
    enum SmalldbgMode { SMALLDBG_MODE_EXTERNAL, SMALLDBG_MODE_INPROCESS };
    enum SmalldbgArch { SMALLDBG_ARCH_X86, SMALLDBG_ARCH_X64, SMALLDBG_ARCH_ARM64 };

    smalldbg::Debugger* smalldbg_create_debugger(enum SmalldbgMode mode, enum SmalldbgArch arch);
    void smalldbg_destroy_debugger(smalldbg::Debugger* d);

    // Basic lifecycle helpers
    int smalldbg_dbg_attach(smalldbg::Debugger* d, uintptr_t pid);
    int smalldbg_dbg_detach(smalldbg::Debugger* d);
}
