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

    // A PE image starts with the MZ header, whose e_lfanew field says where
    // the PE header is; the section table follows the optional header.
    std::vector<smalldbg::ModuleSection> moduleSections(
        const MemoryReader& read, uint64_t base, uint64_t end) {
        std::vector<smalldbg::ModuleSection> sections;
        IMAGE_DOS_HEADER dos{};
        if (!read(base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
            return sections;
        const uint64_t pe = base + static_cast<uint32_t>(dos.e_lfanew);
        DWORD signature = 0;
        IMAGE_FILE_HEADER file{};
        if (!read(pe, &signature, sizeof signature)
            || signature != IMAGE_NT_SIGNATURE
            || !read(pe + sizeof signature, &file, sizeof file))
            return sections;

        uint64_t at = pe + sizeof signature + sizeof file
                    + file.SizeOfOptionalHeader;
        for (WORD i = 0; i < file.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER header{};
            if (!read(at + i * sizeof header, &header, sizeof header)) break;
            DWORD span = header.Misc.VirtualSize ? header.Misc.VirtualSize
                                                 : header.SizeOfRawData;
            smalldbg::ModuleSection section;
            section.name.assign(reinterpret_cast<const char*>(header.Name),
                                strnlen(reinterpret_cast<const char*>(header.Name),
                                        IMAGE_SIZEOF_SHORT_NAME));
            section.start = base + header.VirtualAddress;
            section.end = std::min<uint64_t>(section.start + span, end);
            section.executable =
                (header.Characteristics
                 & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
            if (header.VirtualAddress != 0 && section.end > section.start)
                sections.push_back(std::move(section));
        }
        return sections;
    }
}
