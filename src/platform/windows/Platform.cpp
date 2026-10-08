// Windows platform helpers implementation
#include "platform/Platform.h"
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <initializer_list>

namespace smalldbg_internal {
    uint64_t current_pid() {
        return static_cast<uint64_t>(::GetCurrentProcessId());
    }

    static std::string lowered(const std::string& text) {
        std::string lower = text;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return lower;
    }

    static bool startsWithAny(const std::string& text,
                              std::initializer_list<const char*> prefixes) {
        for (const char* prefix : prefixes)
            if (text.compare(0, std::strlen(prefix), prefix) == 0) return true;
        return false;
    }

    bool isThreadStarter(const std::string& module, const std::string& function) {
        std::string name = lowered(module);
        // Application Verifier hooks thread creation, so its shims sit below a
        // thread's own starter on every stack it watches.
        if (startsWithAny(name, {"vfbasics", "vfcompat", "vfluapriv", "vfnet",
                                 "vfntlmless", "vfprint", "vfsnapshot",
                                 "vfcuzz", "vrfcore", "verifier"}))
            return true;
        // Under WoW64 the 32-bit ntdll is loaded under another name, such as
        // ntdll32.
        if (name.compare(0, 5, "ntdll") == 0)
            return startsWithAny(function, {"RtlUserThreadStart",
                                            "_RtlUserThreadStart",
                                            "__RtlUserThreadStart"});
        if (name == "kernel32")
            return startsWithAny(function, {"BaseThreadInitThunk"});
        if (name == "ucrtbase" || name == "msvcrt")
            return startsWithAny(function, {"thread_start", "_beginthreadex"});
        return false;
    }
}
