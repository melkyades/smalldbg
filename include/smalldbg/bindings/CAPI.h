// C API (C-ABI) bindings for SmallDBG — generic C-style wrappers for foreign runtimes
#pragma once

#include "../Debugger.h"

extern "C" {
    // Create/destroy a Debugger (mode should match smalldbg::Mode enum values)
    // Create a debugger instance. 'mode' and 'arch' should match smalldbg::Mode and smalldbg::Arch values
    // Example: smalldbg_create_debugger(static_cast<int>(smalldbg::Mode::External), static_cast<int>(smalldbg::Arch::X64))
    smalldbg::Debugger* smalldbg_create_debugger(int mode, int arch);
    void smalldbg_destroy_debugger(smalldbg::Debugger* d);

    // Basic lifecycle helpers
    int smalldbg_dbg_attach(smalldbg::Debugger* d, int pid);
    int smalldbg_dbg_detach(smalldbg::Debugger* d);
}
