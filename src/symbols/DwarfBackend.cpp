// DwarfBackend — Symbol resolution from object file symbol tables.
//
// Uses ObjectFileParser (MachOParser on macOS, ElfParser on Linux) to
// read symbol tables from each loaded module and resolve addresses to
// function names.

#include "DwarfBackend.h"
#include "SymbolsInternal.h"
#include "ObjectFileParser.h"
#include "../backends/Backend.h"
#include "../../include/smalldbg/SymbolProvider.h"
#include <algorithm>

namespace smalldbg {

// ---------------------------------------------------------------------------
// DwarfBackend lifecycle
// ---------------------------------------------------------------------------

DwarfBackend::DwarfBackend(Backend* be)
    : backend(be), processHandle(nullptr), initialized(false) {
}

DwarfBackend::~DwarfBackend() {
}

Status DwarfBackend::initialize(void* procHandle, const SymbolOptions& options) {
    processHandle = procHandle;
    (void)options;
    initialized = true;
    return Status::Ok;
}

void DwarfBackend::shutdown() {
    initialized = false;
    processHandle = nullptr;
    modules.clear();
}

// ---------------------------------------------------------------------------
// Module loading — delegates parsing to ObjectFileParser
// ---------------------------------------------------------------------------

void DwarfBackend::loadModules() {
    if (modulesLoaded) return;
    modulesLoaded = true;

    auto parser = ObjectFileParser::create();
    auto infos = backend->enumerateModules();

    for (auto& info : infos) {
        if (info.path.empty()) continue;
        loadOneModule(*parser, info);
    }
}

void DwarfBackend::loadOneModule(ObjectFileParser& parser,
                                  const ModuleInfo& info) {
    int64_t slide = parser.computeSlide(info.path, info.loadAddress);

    auto mod = std::make_unique<ModuleSymbols>();
    mod->path = info.path;
    mod->shortName = filenameOf(info.path);
    mod->loadAddress = info.loadAddress;
    parser.parseFile(info.path, slide, *mod);
    if (!mod->symbols.empty())
        modules.push_back(std::move(mod));
}

// ---------------------------------------------------------------------------
// Symbol helpers
// ---------------------------------------------------------------------------

static Symbol makeSymbol(const ResolvedSymbol& sym, const std::string& modName) {
    Symbol result;
    result.name = sym.name;
    result.address = sym.address;
    result.size = sym.size;
    result.moduleName = modName;
    result.type = SymbolType::Function;
    return result;
}

// ---------------------------------------------------------------------------
// Symbol lookup
// ---------------------------------------------------------------------------

std::optional<Symbol> DwarfBackend::getSymbolByName(const std::string& name) {
    loadModules();

    // 1. Exact match on demangled name
    for (auto& mod : modules) {
        auto it = mod->nameIndex.find(name);
        if (it != mod->nameIndex.end())
            return makeSymbol(mod->symbols[it->second], mod->shortName);
    }

    // 2. Exact match on raw/mangled name
    for (auto& mod : modules) {
        auto it = mod->rawNameIndex.find(name);
        if (it != mod->rawNameIndex.end())
            return makeSymbol(mod->symbols[it->second], mod->shortName);
    }

    // 3. Suffix match: "debugRuntime" matches "Egg::debugRuntime"
    std::string suffix = "::" + name;
    for (auto& mod : modules) {
        for (auto& sym : mod->symbols) {
            if (sym.name.size() > suffix.size() &&
                sym.name.compare(sym.name.size() - suffix.size(),
                                 suffix.size(), suffix) == 0)
                return makeSymbol(sym, mod->shortName);
        }
    }

    return std::nullopt;
}

std::optional<Symbol> DwarfBackend::getSymbolByAddress(Address addr) {
    loadModules();
    for (auto& mod : modules) {
        if (addr < mod->loadAddress) continue;
        if (mod->textEnd != 0 && addr >= mod->textEnd) continue;

        const ResolvedSymbol* found = mod->findSymbol(addr);
        if (!found) continue;

        // Sanity: don't match if too far from the symbol start
        if (found->size > 0 && addr >= found->address + found->size) continue;

        return makeSymbol(*found, mod->shortName);
    }
    return std::nullopt;
}

void DwarfBackend::enumerateSymbols(const std::string& pattern,
                                     SymbolCallback callback) {
    loadModules();
    for (auto& mod : modules) {
        for (auto& sym : mod->symbols) {
            if (sym.name.find(pattern) != std::string::npos) {
                if (!callback(makeSymbol(sym, mod->shortName))) return;
            }
        }
    }
}

void DwarfBackend::enumerateModules(ModuleCallback callback) {
    loadModules();
    for (auto& mod : modules) {
        ModuleInfo info;
        info.path = mod->path;
        info.shortName = mod->shortName;
        info.loadAddress = mod->loadAddress;
        info.endAddress = mod->textEnd;
        info.symbolCount = mod->symbols.size();
        if (!callback(info)) return;
    }
}

std::optional<SourceLocation> DwarfBackend::getSourceLocation(Address addr) {
    (void)addr;
    return std::nullopt;
}

void DwarfBackend::getLocalVariables(StackFrame* frame) {
    loadTypeInfo();

    if (frame->functionName.empty()) return;

    auto* sub = typeDb.findSubprogramByName(frame->functionName);
    if (!sub) return;

    for (auto& dvar : sub->variables) {
        if (dvar.locationType == VariableLocation::Unknown) continue;

        LocalVariable lv;
        lv.name = dvar.name;
        lv.typeName = dvar.typeName;
        lv.size = dvar.typeSize > 0 ? dvar.typeSize : 8;
        lv.locationType = dvar.locationType;
        lv.offset = (dvar.locationType == VariableLocation::Register)
                    ? static_cast<int64_t>(dvar.dwarfRegNum)
                    : dvar.locationOffset;
        lv.frame = frame;
        frame->localVariables.push_back(std::move(lv));
    }
}

void DwarfBackend::loadTypeInfo() {
    if (typeDb.isLoaded()) return;
    loadModules();

    if (!modules.empty())
        typeDb.loadFromBinary(modules[0]->path);
}

const NativeTypeInfo* DwarfBackend::getTypeByName(const std::string& name) {
    loadTypeInfo();
    return typeDb.findType(name);
}

std::optional<std::string> DwarfBackend::getVariableTypeName(const std::string& name) {
    loadTypeInfo();
    return typeDb.getVariableTypeName(name);
}

} // namespace smalldbg
