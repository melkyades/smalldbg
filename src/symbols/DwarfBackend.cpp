// DwarfBackend — Symbol resolution from object file symbol tables.
//
// Uses ObjectFileParser (MachOParser on macOS, ElfParser on Linux) to
// read symbol tables from each loaded module and resolve addresses to
// function names.

#include "DwarfBackend.h"
#include "SymbolsInternal.h"
#include "ModuleKey.h"
#include "Glob.h"
#include "ObjectFileParser.h"
#include "../backends/Backend.h"
#include "../../include/smalldbg/symbols/SymbolProvider.h"
#include "../../include/smalldbg/StackTrace.h"
#include "../platform/SourceResolver.h"
#include <algorithm>

namespace smalldbg {

// ---------------------------------------------------------------------------
// DwarfBackend lifecycle
// ---------------------------------------------------------------------------

DwarfBackend::DwarfBackend(Backend* be)
    : backend(be), processHandle(nullptr), initialized(false),
      parser(ObjectFileParser::create()) {
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
    modulesVersion = 0;
    typeDatabases.clear();
    sourceLocationCache.clear();
}

// ---------------------------------------------------------------------------
// Module loading — delegates parsing to ObjectFileParser
// ---------------------------------------------------------------------------

void DwarfBackend::loadModules() {
    uint64_t version = backend->targetVersion();
    if (modulesVersion == version) return;
    modulesVersion = version;

    // A launched target stops before the loader has mapped anything, so the
    // modules are asked for again whenever the target may have moved. Those
    // already known are kept, with whatever was read of them.
    std::vector<std::unique_ptr<ModuleSymbols>> current;
    for (auto& info : backend->enumerateModules()) {
        if (info.path.empty()) continue;
        current.push_back(takeOrLoadModule(info));
    }
    if (current.size() != modules.size()) sourceLocationCache.clear();
    modules = std::move(current);

    // The executable's symbols are the ones most asked for, by name too.
    if (!modules.empty()) symbolsOf(*modules[0]);
}

std::unique_ptr<ModuleSymbols> DwarfBackend::takeOrLoadModule(const ModuleInfo& info) {
    auto known = std::find_if(modules.begin(), modules.end(),
        [&](const std::unique_ptr<ModuleSymbols>& mod) {
            return mod && mod->path == info.path
                && mod->loadAddress == info.loadAddress;
        });
    if (known != modules.end()) return std::move(*known);
    return loadOneModule(info);
}

smalldbg_internal::MemoryReader DwarfBackend::targetMemory() const {
    return [this](uint64_t address, void* out, size_t size) {
        return backend->readMemory(address, out, size) == Status::Ok;
    };
}

// An image loaded in the target is read where it is mapped, and only how far
// it reaches until its symbols are asked for: a process maps hundreds of
// libraries and a stack touches a few. An image the parser cannot read in
// memory is read from its file, symbols and all.
std::unique_ptr<ModuleSymbols> DwarfBackend::loadOneModule(const ModuleInfo& info) {
    auto mod = std::make_unique<ModuleSymbols>();
    mod->path = info.path;
    mod->shortName = filenameOf(info.path);
    mod->loadAddress = info.loadAddress;
    mod->textEnd = 0;
    if (parser->readLoadedExtent(targetMemory(), info.loadAddress, *mod)) return mod;

    mod->symbolsRead = true;
    parser->parseFile(info.path, parser->computeSlide(info.path, info.loadAddress), *mod);
    return mod;
}

ModuleSymbols& DwarfBackend::symbolsOf(ModuleSymbols& mod) {
    if (mod.symbolsRead) return mod;
    mod.symbolsRead = true;
    if (!parser->parseLoadedSymbols(targetMemory(), mod.loadAddress, mod))
        parser->parseFile(mod.path, parser->computeSlide(mod.path, mod.loadAddress), mod);
    return mod;
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

    // "module!name" looks in that module only.
    auto bang = name.find('!');
    if (bang != std::string::npos) {
        ModuleSymbols* mod = moduleNamed(name.substr(0, bang));
        if (!mod) return std::nullopt;
        return symbolNamed(symbolsOf(*mod), name.substr(bang + 1));
    }

    for (auto& mod : modules)
        if (auto found = symbolNamed(symbolsOf(*mod), name)) return found;
    return std::nullopt;
}

ModuleSymbols* DwarfBackend::moduleNamed(const std::string& module) {
    std::string wanted = moduleKey(module);
    for (auto& mod : modules)
        if (moduleKey(mod->shortName) == wanted) return mod.get();
    return nullptr;
}

std::optional<Symbol> DwarfBackend::symbolNamed(const ModuleSymbols& mod,
                                                const std::string& name) {
    // Exact match on the demangled name, then on the raw (mangled) one
    for (auto* index : {&mod.nameIndex, &mod.rawNameIndex}) {
        auto it = index->find(name);
        if (it != index->end()) return makeSymbol(mod.symbols[it->second], mod.shortName);
    }

    // Suffix match: "doSomething" matches "MyApp::doSomething"
    std::string suffix = "::" + name;
    for (auto& sym : mod.symbols) {
        if (sym.name.size() > suffix.size() &&
            sym.name.compare(sym.name.size() - suffix.size(), suffix.size(), suffix) == 0)
            return makeSymbol(sym, mod.shortName);
    }
    return std::nullopt;
}

bool DwarfBackend::loadModuleSymbols(const std::string& module, SymbolMatch match) {
    (void)match;  // the symbols are the module's own, read off its image
    loadModules();
    ModuleSymbols* mod = moduleNamed(module);
    return mod && !symbolsOf(*mod).symbols.empty();
}

std::optional<Symbol> DwarfBackend::getSymbolByAddress(Address addr) {
    loadModules();
    for (auto& mod : modules) {
        if (addr < mod->loadAddress) continue;
        if (mod->textEnd != 0 && addr >= mod->textEnd) continue;

        const ResolvedSymbol* found = symbolsOf(*mod).findSymbol(addr);
        if (!found) continue;

        // Sanity: don't match if too far from the symbol start
        if (found->size > 0 && addr >= found->address + found->size) continue;

        return makeSymbol(*found, mod->shortName);
    }
    return std::nullopt;
}

// `pattern` is "name" or "module!name", each part with '*' and '?'. A pattern
// without a module is matched in the modules whose symbols are read already,
// rather than having every library's read to match it.
void DwarfBackend::enumerateSymbols(const std::string& pattern,
                                     SymbolCallback callback) {
    loadModules();
    auto bang = pattern.find('!');
    bool qualified = bang != std::string::npos;
    std::string modulePattern = qualified ? pattern.substr(0, bang) : "*";
    std::string namePattern = qualified ? pattern.substr(bang + 1) : pattern;
    for (auto& mod : modules) {
        bool named = globMatches(modulePattern.c_str(), mod->shortName.c_str())
                     || globMatches(modulePattern.c_str(), moduleKey(mod->shortName).c_str());
        if (!named || (!qualified && !mod->symbolsRead)) continue;
        if (!enumerateModuleSymbols(symbolsOf(*mod), namePattern, callback)) return;
    }
}

// Answers false when the callback asked to stop.
bool DwarfBackend::enumerateModuleSymbols(const ModuleSymbols& mod,
                                          const std::string& pattern,
                                          const SymbolCallback& callback) {
    for (auto& sym : mod.symbols)
        if (globMatches(pattern.c_str(), sym.name.c_str())
            && !callback(makeSymbol(sym, mod.shortName)))
            return false;
    return true;
}

// A module whose symbols are not read yet says so, as an engine says of one
// it defers.
void DwarfBackend::enumerateModules(ModuleCallback callback) {
    loadModules();
    for (auto& mod : modules) {
        ModuleInfo info;
        info.path = mod->path;
        info.shortName = mod->shortName;
        info.loadAddress = mod->loadAddress;
        info.endAddress = mod->textEnd;
        info.symbolCount = mod->symbols.size();
        info.symbolType = !mod->symbolsRead ? "deferred"
                        : info.symbolCount > 0 ? "symtab" : "none";
        if (info.symbolCount > 0) info.symbolFile = mod->path;
        if (!callback(info)) return;
    }
}

std::optional<SourceLocation> DwarfBackend::getSourceLocation(Address addr) {
    auto cacheIt = sourceLocationCache.find(addr);
    if (cacheIt != sourceLocationCache.end())
        return cacheIt->second;

    loadModules();

    for (auto& mod : modules) {
        if (addr >= mod->loadAddress && (mod->textEnd == 0 || addr < mod->textEnd)) {
            auto result = resolveSourceLocation(mod->path, mod->loadAddress, addr);
            sourceLocationCache[addr] = result;
            return result;
        }
    }

    sourceLocationCache[addr] = std::nullopt;
    return std::nullopt;
}

void DwarfBackend::getLocalVariables(StackFrame* frame) {
    if (frame->functionName.empty()) return;
    const DwarfTypeDatabase* types = mainTypes();
    if (!types) return;

    auto* sub = types->findSubprogramByName(frame->functionName);
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

// The types a module's DWARF describes, read the first time they are asked
// for.
const DwarfTypeDatabase* DwarfBackend::typesOf(const ModuleSymbols& mod) {
    auto& types = typeDatabases[mod.path];
    if (!types) {
        types = std::make_unique<DwarfTypeDatabase>();
        types->loadFromBinary(mod.path);
    }
    return types.get();
}

// The executable's types: a name without a module is looked up there. The
// executable is the first module dyld lists.
const DwarfTypeDatabase* DwarfBackend::mainTypes() {
    loadModules();
    return modules.empty() ? nullptr : typesOf(*modules[0]);
}

// The types `name` is looked up in, "module!" taken off it: those of that
// module, or the executable's when it names none.
const DwarfTypeDatabase* DwarfBackend::typesFor(std::string& name, std::string& module) {
    auto bang = name.find('!');
    if (bang == std::string::npos) return mainTypes();

    module = name.substr(0, bang);
    name = name.substr(bang + 1);
    loadModules();
    ModuleSymbols* mod = moduleNamed(module);
    return mod ? typesOf(*mod) : nullptr;
}

const NativeTypeInfo* DwarfBackend::getTypeByName(const std::string& name) {
    std::string typeName = name, module;
    const DwarfTypeDatabase* types = typesFor(typeName, module);
    return types ? types->findType(typeName) : nullptr;
}

// A module-qualified variable answers its type qualified the same way, so
// that the type is looked up in the module that declares it.
std::optional<std::string> DwarfBackend::getVariableTypeName(const std::string& name) {
    std::string variable = name, module;
    const DwarfTypeDatabase* types = typesFor(variable, module);
    if (!types) return std::nullopt;
    auto typeName = types->getVariableTypeName(variable);
    if (!typeName || module.empty()) return typeName;
    return module + "!" + *typeName;
}

} // namespace smalldbg
