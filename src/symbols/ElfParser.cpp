// ElfParser — Linux ELF object file parser.
// Extracts symbol tables from ELF binaries (.symtab / .dynsym).

#include "ObjectFileParser.h"
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <algorithm>

namespace smalldbg {

class ElfParser : public ObjectFileParser {
public:
    bool parseFile(const std::string& path, int64_t slide,
                   ModuleSymbols& out) override;
    int64_t computeSlide(const std::string& path,
                         Address loadAddress) override;

private:
    // Parse a symbol table section and append symbols to the output.
    static void parseSymtab(const uint8_t* base, size_t fileSize,
                            const Elf64_Shdr* symtabHdr,
                            const Elf64_Shdr* strtabHdr,
                            int64_t slide,
                            std::vector<ResolvedSymbol>& symbols);

    // Process one ELF symbol entry.
    static void processSymEntry(const Elf64_Sym& sym,
                                const char* strtab, uint32_t strsize,
                                int64_t slide,
                                std::vector<ResolvedSymbol>& symbols);
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

std::unique_ptr<ObjectFileParser> ObjectFileParser::create() {
    return std::make_unique<ElfParser>();
}

// ---------------------------------------------------------------------------
// Symbol processing
// ---------------------------------------------------------------------------

void ElfParser::processSymEntry(const Elf64_Sym& sym,
                                 const char* strtab, uint32_t strsize,
                                 int64_t slide,
                                 std::vector<ResolvedSymbol>& symbols) {
    // Only interested in defined symbols with a section index
    if (sym.st_shndx == SHN_UNDEF) return;
    if (sym.st_name == 0 || sym.st_name >= strsize) return;

    uint8_t type = ELF64_ST_TYPE(sym.st_info);
    // Accept functions and objects (global variables)
    if (type != STT_FUNC && type != STT_OBJECT) return;

    const char* name = strtab + sym.st_name;
    if (name[0] == '\0') return;

    ResolvedSymbol rsym;
    rsym.address = sym.st_value + slide;
    rsym.rawName = name;
    rsym.name = demangle(name);
    rsym.size = sym.st_size;
    symbols.push_back(std::move(rsym));
}

void ElfParser::parseSymtab(const uint8_t* base, size_t fileSize,
                             const Elf64_Shdr* symtabHdr,
                             const Elf64_Shdr* strtabHdr,
                             int64_t slide,
                             std::vector<ResolvedSymbol>& symbols) {
    if (symtabHdr->sh_offset + symtabHdr->sh_size > fileSize) return;
    if (strtabHdr->sh_offset + strtabHdr->sh_size > fileSize) return;

    size_t numSyms = symtabHdr->sh_size / sizeof(Elf64_Sym);
    auto* syms = reinterpret_cast<const Elf64_Sym*>(base + symtabHdr->sh_offset);
    auto* strtab = reinterpret_cast<const char*>(base + strtabHdr->sh_offset);
    uint32_t strsize = static_cast<uint32_t>(strtabHdr->sh_size);

    for (size_t i = 0; i < numSyms; i++)
        processSymEntry(syms[i], strtab, strsize, slide, symbols);
}

// ---------------------------------------------------------------------------
// parseFile — parse an ELF binary
// ---------------------------------------------------------------------------

bool ElfParser::parseFile(const std::string& path, int64_t slide,
                           ModuleSymbols& out) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    size_t fileSize = static_cast<size_t>(st.st_size);
    if (fileSize < sizeof(Elf64_Ehdr)) { close(fd); return false; }

    void* mapped = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return false;

    auto* base = static_cast<const uint8_t*>(mapped);
    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);

    // Validate ELF magic
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        munmap(mapped, fileSize);
        return false;
    }

    // Find .text segment end for bounds checking
    for (int i = 0; i < ehdr->e_phnum; i++) {
        auto* phdr = reinterpret_cast<const Elf64_Phdr*>(
            base + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
            out.textEnd = phdr->p_vaddr + phdr->p_memsz + slide;
            break;
        }
    }

    // Walk section headers to find symbol tables
    if (ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize > fileSize) {
        munmap(mapped, fileSize);
        return false;
    }

    auto sectionAt = [&](uint16_t idx) -> const Elf64_Shdr* {
        return reinterpret_cast<const Elf64_Shdr*>(
            base + ehdr->e_shoff + idx * ehdr->e_shentsize);
    };

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        auto* shdr = sectionAt(i);
        if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
            if (shdr->sh_link < ehdr->e_shnum) {
                auto* strHdr = sectionAt(static_cast<uint16_t>(shdr->sh_link));
                parseSymtab(base, fileSize, shdr, strHdr, slide, out.symbols);
            }
        }
    }

    munmap(mapped, fileSize);

    // Sort by address
    std::sort(out.symbols.begin(), out.symbols.end(),
        [](const ResolvedSymbol& a, const ResolvedSymbol& b) {
            return a.address < b.address;
        });

    // Estimate sizes from gaps where not already set
    for (size_t i = 0; i + 1 < out.symbols.size(); i++) {
        if (out.symbols[i].size == 0)
            out.symbols[i].size = out.symbols[i + 1].address - out.symbols[i].address;
    }
    if (!out.symbols.empty() && out.symbols.back().size == 0)
        out.symbols.back().size = 1;

    out.buildNameIndexes();
    return !out.symbols.empty();
}

// ---------------------------------------------------------------------------
// computeSlide — compare on-disk .text vaddr with runtime load address
// ---------------------------------------------------------------------------

int64_t ElfParser::computeSlide(const std::string& path, Address loadAddress) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    uint8_t buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < static_cast<ssize_t>(sizeof(Elf64_Ehdr))) return 0;

    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(buf);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;

    // Find the first PT_LOAD segment (typically .text)
    size_t phOff = ehdr->e_phoff;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        size_t off = phOff + i * ehdr->e_phentsize;
        if (off + sizeof(Elf64_Phdr) > static_cast<size_t>(n)) break;
        auto* phdr = reinterpret_cast<const Elf64_Phdr*>(buf + off);
        if (phdr->p_type == PT_LOAD)
            return static_cast<int64_t>(loadAddress) - static_cast<int64_t>(phdr->p_vaddr);
    }
    return 0;
}

} // namespace smalldbg
