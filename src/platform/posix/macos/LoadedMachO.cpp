#include "LoadedMachO.h"

#include <mach-o/loader.h>

#include <algorithm>
#include <cstring>

namespace smalldbg_internal {

namespace {

// What the load commands say, in the addresses the image asks for.
struct LoadCommands {
    std::vector<LoadedSection> sections;  // unslid
    uint64_t textAddress{0};
    uint64_t textSize{0};
    bool hasText{false};
};

bool isExecutable(const section_64& section) {
    return (section.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0;
}

std::string fixedName(const char* name, size_t size) {
    return std::string(name, strnlen(name, size));
}

void addSection(const section_64& section, LoadCommands& commands) {
    LoadedSection loaded;
    loaded.name = fixedName(section.segname, sizeof section.segname) + ","
                + fixedName(section.sectname, sizeof section.sectname);
    loaded.start = section.addr;
    loaded.end = section.addr + section.size;
    loaded.executable = isExecutable(section);
    if (loaded.end > loaded.start) commands.sections.push_back(std::move(loaded));
}

void addSegment(const segment_command_64& segment, const uint8_t* end,
                LoadCommands& commands) {
    std::string name = fixedName(segment.segname, sizeof segment.segname);
    if (name == SEG_TEXT) {
        commands.textAddress = segment.vmaddr;
        commands.textSize = segment.vmsize;
        commands.hasText = true;
    }

    auto* sections = reinterpret_cast<const section_64*>(&segment + 1);
    for (uint32_t i = 0; i < segment.nsects; i++) {
        if (reinterpret_cast<const uint8_t*>(sections + i + 1) > end) return;
        addSection(sections[i], commands);
    }
}

// Answers false when the commands run past what was read.
bool readCommands(const std::vector<uint8_t>& bytes, uint32_t count,
                  LoadCommands& commands) {
    const uint8_t* end = bytes.data() + bytes.size();
    const uint8_t* at = bytes.data();
    for (uint32_t i = 0; i < count; i++) {
        auto* command = reinterpret_cast<const load_command*>(at);
        if (at + sizeof(load_command) > end || at + command->cmdsize > end
            || command->cmdsize < sizeof(load_command))
            return false;
        if (command->cmd == LC_SEGMENT_64)
            addSegment(*reinterpret_cast<const segment_command_64*>(at), end, commands);
        at += command->cmdsize;
    }
    return true;
}

} // namespace

bool readLoadedMachO(const MemoryReader& read, uint64_t base, LoadedMachO& image) {
    mach_header_64 header{};
    if (!read(base, &header, sizeof header) || header.magic != MH_MAGIC_64)
        return false;
    std::vector<uint8_t> bytes(header.sizeofcmds);
    if (!read(base + sizeof header, bytes.data(), bytes.size())) return false;

    LoadCommands commands;
    if (!readCommands(bytes, header.ncmds, commands) || !commands.hasText) return false;

    image.slide = static_cast<int64_t>(base - commands.textAddress);
    image.textEnd = commands.textAddress + commands.textSize + image.slide;
    for (auto& section : commands.sections) {
        section.start += image.slide;
        section.end += image.slide;
        image.sections.push_back(std::move(section));
    }

    return true;
}

// Sections are named "__SEGMENT,__section", as the linker names them.
std::vector<smalldbg::ModuleSection> moduleSections(const MemoryReader& read,
                                                    uint64_t base, uint64_t end) {
    std::vector<smalldbg::ModuleSection> sections;
    LoadedMachO image;
    if (!readLoadedMachO(read, base, image)) return sections;
    for (const auto& loaded : image.sections) {
        smalldbg::ModuleSection section;
        section.name = loaded.name;
        section.start = loaded.start;
        section.end = end ? std::min(loaded.end, end) : loaded.end;
        section.executable = loaded.executable;
        if (section.end > section.start) sections.push_back(std::move(section));
    }
    return sections;
}

} // namespace smalldbg_internal
