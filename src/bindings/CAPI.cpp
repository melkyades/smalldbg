#include "smalldbg/bindings/CAPI.h"

using namespace smalldbg;

extern "C" {

    Debugger* smalldbg_create_debugger(int mode, int arch) {
        return new Debugger(static_cast<Mode>(mode), static_cast<Arch>(arch));
    }

    void smalldbg_destroy_debugger(Debugger* d) {
        delete d;
    }

    int smalldbg_dbg_attach(Debugger* d, int pid) {
        if (!d) return -1;
        return static_cast<int>(d->attach(pid));
    }

    int smalldbg_dbg_detach(Debugger* d) {
        if (!d) return -1;
        return static_cast<int>(d->detach());
    }

}
