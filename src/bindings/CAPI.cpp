#include "smalldbg/bindings/CAPI.h"

using namespace smalldbg;

extern "C" {

    Debugger* smalldbg_create_debugger(enum SmalldbgMode mode, enum SmalldbgArch arch) {
        static const Arch* archs[] = { X86::instance(), X64::instance(), ARM64::instance() };
        return new Debugger(static_cast<Mode>(mode), archs[arch]);
    }

    void smalldbg_destroy_debugger(Debugger* d) {
        delete d;
    }

    int smalldbg_dbg_attach(Debugger* d, uintptr_t pid) {
        if (!d) return -1;
        return static_cast<int>(d->attach(pid));
    }

    int smalldbg_dbg_detach(Debugger* d) {
        if (!d) return -1;
        return static_cast<int>(d->detach());
    }

}
