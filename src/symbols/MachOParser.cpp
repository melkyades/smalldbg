// MachOParser — macOS Mach-O object file parser.
// Extracts symbol tables from Mach-O and fat binaries.

#include "ObjectFileParser.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <algorithm>

namespace smalldbg {

class MachOParser : public ObjectFileParser {
public:
    bool parseFile(const std::string& path, int64_t slide,
                   ModuleSymbols& out) override;
    int64_t computeSlide(const std::string& path,
                         Address loadAddress) override;

private:
    // Parse a single 64-bit Mach-O image at the given base pointer.
    static void parseMachO64(const uint8_t* base, size_t fileSize,
                             int64_t slide, ModuleSymbols& out);

    // Process one nlist entry and append to symbols if it qualifies.
    static void processNlistEntry(const struct nlist_64& nl,
                                  const char* strtab, uint32_t strsize,
                                  int64_t slide,
                                  std::vector<ResolvedSymbol>& symbols);
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<ObjectFileParser> ObjectFileParser::create() {
    return std::make_unique<MachOParser>();
}

// ---------------------------------------------------------------------------
// parseMachO64
// ---------------------------------------------------------------------------

void MachOParser::processNlistEntry(const struct nlist_64& nl,
                                     const char* strtab, uint32_t strsize,
                                     int64_t slide,
                                     std::vector<ResolvedSymbol>& symbols) {
    // Skip debug symbols, undefined, and non-section symbols
    if (nl.n_type & N_STAB) return;
    if ((nl.n_type & N_TYPE) == N_UNDF) return;
    if ((nl.n_type & N_TYPE) != N_SECT) return;

    uint32_t strIdx = nl.n_un.n_strx;
    if (strIdx >= strsize) return;
    const char* name = strtab + strIdx;
    if (name[0] == '\0') return;

    // Skip leading underscore (C/C++ symbols on macOS)
    const char* stripped = (name[0] == '_') ? name + 1 : name;

    ResolvedSymbol sym;
    sym.address = nl.n_value + slide;
    sym.rawName = stripped;
    sym.name = demangle(stripped);
    sym.size = 0;
    symbols.push_back(std::move(sym));
}

void MachOParser::parseMachO64(const uint8_t* base, size_t fileSize,
                                int64_t slide, ModuleSymbols& out) {
    auto* header = reinterpret_cast<const mach_header_64*>(base);
    if (header->magic != MH_MAGIC_64) return;

    // Walk load commands to find LC_SYMTAB and __TEXT segment bounds
    const uint8_t* cmd = base + sizeof(mach_header_64);
    const struct symtab_command* symtab = nullptr;
    uint64_t textVmaddr = 0, textVmsize = 0;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        auto* lc = reinterpret_cast<const load_command*>(cmd);
        if (cmd + sizeof(load_command) > base + fileSize) break;

        if (lc->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<const struct symtab_command*>(cmd);
        } else if (lc->cmd == LC_SEGMENT_64) {
            auto* seg = reinterpret_cast<const segment_command_64*>(cmd);
            if (std::strncmp(seg->segname, "__TEXT", 6) == 0) {
                textVmaddr = seg->vmaddr;
                textVmsize = seg->vmsize;
            }
        }
        cmd += lc->cmdsize;
    }

    out.textEnd = textVmaddr + textVmsize + slide;

    if (!symtab || symtab->nsyms == 0) return;
    if (symtab->symoff + symtab->nsyms * sizeof(nlist_64) > fileSize) return;
    if (symtab->stroff + symtab->strsize > fileSize) return;

    auto* nlists = reinterpret_cast<const nlist_64*>(base + symtab->symoff);
    auto* strtab = reinterpret_cast<const char*>(base + symtab->stroff);

    out.symbols.reserve(symtab->nsyms / 2);

    for (uint32_t i = 0; i < symtab->nsyms; i++)
        processNlistEntry(nlists[i], strtab, symtab->strsize, slide, out.symbols);

    // Sort by address
    std::sort(out.symbols.begin(), out.symbols.end(),
        [](const ResolvedSymbol& a, const ResolvedSymbol& b) {
            return a.address < b.address;
        });

    // Estimate sizes from gaps between consecutive symbols
    for (size_t i = 0; i + 1 < out.symbols.size(); i++)
        out.symbols[i].size = out.symbols[i + 1].address - out.symbols[i].address;
    if (!out.symbols.empty())
        out.symbols.back().size = 1;
}

// ---------------------------------------------------------------------------
// parseFile — handles fat binaries and single-arch Mach-O
// ---------------------------------------------------------------------------

bool MachOParser::parseFile(const std::string& path, int64_t slide,
                             ModuleSymbols& out) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    size_t fileSize = static_cast<size_t>(st.st_size);
    if (fileSize < sizeof(mach_header_64)) { close(fd); return false; }

    void* mapped = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return false;

    auto* base = static_cast<const uint8_t*>(mapped);
    uint32_t magic = *reinterpret_cast<const uint32_t*>(base);

    if (magic == MH_MAGIC_64) {
        parseMachO64(base, fileSize, slide, out);
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        auto* fatHeader = reinterpret_cast<const fat_header*>(base);
        uint32_t nArch = OSSwapBigToHostInt32(fatHeader->nfat_arch);
        auto* arches = reinterpret_cast<const fat_arch*>(base + sizeof(fat_header));
        for (uint32_t i = 0; i < nArch; i++) {
            cpu_type_t cpuType = OSSwapBigToHostInt32(arches[i].cputype);
#if defined(__arm64__) || defined(__aarch64__)
            if (cpuType == CPU_TYPE_ARM64) {
#else
            if (cpuType == CPU_TYPE_X86_64) {
#endif
                uint32_t offset = OSSwapBigToHostInt32(arches[i].offset);
                uint32_t size = OSSwapBigToHostInt32(arches[i].size);
                if (offset + size <= fileSize)
                    parseMachO64(base + offset, size, slide, out);
                break;
            }
        }
    }

    munmap(mapped, fileSize);
    out.buildNameIndexes();
    return !out.symbols.empty();
}

// ---------------------------------------------------------------------------
// computeSlide — compare on-disk __TEXT vmaddr with runtime load address
// ---------------------------------------------------------------------------

int64_t MachOParser::computeSlide(const std::string& path, Address loadAddress) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    uint8_t buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < static_cast<ssize_t>(sizeof(mach_header_64))) return 0;

    const uint8_t* base = buf;
    size_t size = static_cast<size_t>(n);
    uint32_t magic = *reinterpret_cast<const uint32_t*>(base);

    // Handle fat binary header
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        auto* fatHeader = reinterpret_cast<const fat_header*>(base);
        uint32_t nArch = OSSwapBigToHostInt32(fatHeader->nfat_arch);
        auto* arches = reinterpret_cast<const fat_arch*>(base + sizeof(fat_header));
        for (uint32_t i = 0; i < nArch; i++) {
            cpu_type_t cpuType = OSSwapBigToHostInt32(arches[i].cputype);
#if defined(__arm64__) || defined(__aarch64__)
            if (cpuType == CPU_TYPE_ARM64) {
#else
            if (cpuType == CPU_TYPE_X86_64) {
#endif
                uint32_t offset = OSSwapBigToHostInt32(arches[i].offset);
                int fd2 = open(path.c_str(), O_RDONLY);
                if (fd2 < 0) return 0;
                lseek(fd2, offset, SEEK_SET);
                n = read(fd2, buf, sizeof(buf));
                close(fd2);
                if (n < static_cast<ssize_t>(sizeof(mach_header_64))) return 0;
                size = static_cast<size_t>(n);
                break;
            }
        }
        magic = *reinterpret_cast<const uint32_t*>(buf);
    }

    if (magic != MH_MAGIC_64) return 0;

    auto* header = reinterpret_cast<const mach_header_64*>(buf);
    const uint8_t* cmd = buf + sizeof(mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        auto* lc = reinterpret_cast<const load_command*>(cmd);
        if (cmd + sizeof(load_command) > buf + size) break;
        if (lc->cmd == LC_SEGMENT_64) {
            auto* seg = reinterpret_cast<const segment_command_64*>(cmd);
            if (std::strncmp(seg->segname, "__TEXT", 6) == 0)
                return static_cast<int64_t>(loadAddress) - static_cast<int64_t>(seg->vmaddr);
        }
        cmd += lc->cmdsize;
    }
    return 0;
}

} // namespace smalldbg
