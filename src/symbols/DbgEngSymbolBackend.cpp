// DbgEng symbol backend — implementation.
//
// Wraps IDebugSymbols3 methods (GetNameByOffset, GetModuleByOffset,
// GetLineByOffset, GetOffsetByName) to implement the SymbolBackend interface.

#include "DbgEngSymbolBackend.h"
#include "ModuleKey.h"
#include "../backends/DbgEngBackend.h"
#include "../../include/smalldbg/StackFrame.h"

// The SYMOPT_ flags IDebugSymbols shares with DbgHelp are declared there.
#include <dbghelp.h>

#include <sstream>
#include <algorithm>

namespace smalldbg {

DbgEngSymbolBackend::DbgEngSymbolBackend(IDebugSymbols3* symbols, IDebugControl4* control)
    : symbols(symbols), control(control)
{
}

DbgEngSymbolBackend::~DbgEngSymbolBackend() {
    shutdown();
}

// Sets the engine's path to the caller's directories, then the path it already
// had, then the symbol server. The caller's go first because a same-named pdb
// from elsewhere would otherwise load, with every symbol at the wrong address.
void DbgEngSymbolBackend::applySearchPath(const std::string& callerPath) {
    if (callerPath.empty() && !options.useSymbolServer) return;

    std::string symPath = callerPath;

    char existingPath[2048] = {};
    ULONG pathSize = 0;
    symbols->GetSymbolPath(existingPath, sizeof(existingPath), &pathSize);
    if (existingPath[0]) {
        if (!symPath.empty()) symPath += ";";
        symPath += existingPath;
    }

    if (options.useSymbolServer) {
        std::string srv = "srv*";
        if (!options.cacheDirectory.empty()) srv += options.cacheDirectory;
        srv += "*" + options.symbolServerUrl;
        if (symPath.find(srv) == std::string::npos) {
            if (!symPath.empty()) symPath += ";";
            symPath += srv;
        }
    }

    symbols->SetSymbolPath(symPath.c_str());
}

Status DbgEngSymbolBackend::initialize(void* /*processHandle*/, const SymbolOptions& opts) {
    options = opts;
    if (!symbols) return Status::Error;

    applySearchPath(opts.searchPath);

    // A name given without its module would otherwise have the engine load
    // every module's symbols to look for it, fetching each from the symbol
    // server. A name with its module still loads that module.
    symbols->AddSymbolOptions(SYMOPT_NO_UNQUALIFIED_LOADS);

    initialized = true;
    return Status::Ok;
}

std::string DbgEngSymbolBackend::searchPath() const {
    if (!symbols) return {};
    char path[4096] = {};
    if (FAILED(symbols->GetSymbolPath(path, sizeof(path), nullptr))) return {};
    return path;
}

void DbgEngSymbolBackend::setSearchPath(const std::string& path) {
    options.searchPath = path;
    if (symbols) applySearchPath(path);
}

// The image file name is what a reload accepts: the engine may report an
// executable's module name as "test_target" yet look it up only as
// "test_target_exe".
bool DbgEngSymbolBackend::findModule(const std::string& module, ULONG64& base,
                                     std::string& imageFile) {
    ULONG loaded = 0, unloaded = 0;
    if (FAILED(symbols->GetNumberModules(&loaded, &unloaded))) return false;

    std::string wanted = moduleKey(module);
    for (ULONG i = 0; i < loaded; ++i) {
        char image[512] = {};
        char name[256] = {};
        symbols->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, 0, image, sizeof(image), nullptr);
        symbols->GetModuleNameString(DEBUG_MODNAME_MODULE, i, 0, name, sizeof(name), nullptr);
        if (moduleKey(image) != wanted && moduleKey(name) != wanted) continue;
        if (FAILED(symbols->GetModuleByIndex(i, &base))) return false;
        std::string path = image;
        imageFile = path.substr(path.find_last_of("\\/") + 1);
        return true;
    }
    return false;
}

bool DbgEngSymbolBackend::loadSymbolsAt(Address addr) {
    ULONG index = 0;
    ULONG64 base = 0;
    if (FAILED(symbols->GetModuleByOffset(addr, 0, &index, &base))) return false;
    if (!symbolsLoadedAt.insert(base).second) return false;

    char image[512] = {};
    if (FAILED(symbols->GetModuleNameString(DEBUG_MODNAME_IMAGE, index, 0, image,
                                            sizeof(image), nullptr)))
        return false;
    std::string path = image;
    std::string imageFile = path.substr(path.find_last_of("\\/") + 1);
    return SUCCEEDED(symbols->Reload(("/f " + imageFile).c_str()));
}

bool DbgEngSymbolBackend::hasSymbolFile(ULONG64 base) {
    DEBUG_MODULE_PARAMETERS params = {};
    if (FAILED(symbols->GetModuleParameters(1, &base, 0, &params))) return false;

    switch (params.SymbolType) {
    case DEBUG_SYMTYPE_PDB:
    case DEBUG_SYMTYPE_DIA:
    case DEBUG_SYMTYPE_CODEVIEW:
    case DEBUG_SYMTYPE_COFF:
    case DEBUG_SYMTYPE_SYM:
        return true;
    default:
        return false;
    }
}

// Reloads the module and checks a symbol file came in. With Nearest, a file
// that is not an exact match is accepted, and stays accepted for the session:
// requiring exact matches again would unload it at the next reload.
bool DbgEngSymbolBackend::loadModuleSymbols(const std::string& module,
                                            SymbolMatch match) {
    if (!symbols) return false;
    ULONG64 base = 0;
    std::string imageFile;
    if (!findModule(module, base, imageFile)) return false;

    if (match == SymbolMatch::Nearest) {
        symbols->RemoveSymbolOptions(SYMOPT_EXACT_SYMBOLS);
        symbols->AddSymbolOptions(SYMOPT_LOAD_ANYTHING);
    }

    std::string spec = match == SymbolMatch::Nearest ? "/i /f " : "/f ";
    symbols->Reload((spec + imageFile).c_str());
    return hasSymbolFile(base);
}

void DbgEngSymbolBackend::shutdown() {
    initialized = false;
}

std::optional<Symbol> DbgEngSymbolBackend::getSymbolByName(const std::string& name) {
    if (!symbols) return std::nullopt;

    ULONG64 offset = 0;
    HRESULT hr = symbols->GetOffsetByName(name.c_str(), &offset);
    if (FAILED(hr)) return std::nullopt;

    Symbol sym;
    sym.name = name;
    sym.address = static_cast<Address>(offset);
    sym.type = SymbolType::Function;

    // Try to get module name
    ULONG moduleIndex = 0;
    ULONG64 moduleBase = 0;
    hr = symbols->GetModuleByOffset(offset, 0, &moduleIndex, &moduleBase);
    if (SUCCEEDED(hr)) {
        char modName[256] = {};
        ULONG modNameSize = 0;
        hr = symbols->GetModuleNameString(
            DEBUG_MODNAME_MODULE, moduleIndex, 0,
            modName, sizeof(modName), &modNameSize);
        if (SUCCEEDED(hr)) {
            sym.moduleName = modName;
        }
    }

    return sym;
}

std::optional<Symbol> DbgEngSymbolBackend::getSymbolByAddress(Address addr) {
    if (!symbols) return std::nullopt;

    // GetNameByOffset returns "module!function" format
    char nameBuf[512] = {};
    ULONG nameSize = 0;
    ULONG64 displacement = 0;
    HRESULT hr = symbols->GetNameByOffset(
        static_cast<ULONG64>(addr),
        nameBuf, sizeof(nameBuf), &nameSize,
        &displacement);
    if (FAILED(hr)) return std::nullopt;

    std::string fullName = nameBuf;
    if (fullName.empty()) return std::nullopt;

    // A module whose symbols are not loaded yet is named alone, with no
    // function: load them and ask again.
    if (fullName.find('!') == std::string::npos && loadSymbolsAt(addr)) {
        hr = symbols->GetNameByOffset(static_cast<ULONG64>(addr), nameBuf,
                                      sizeof(nameBuf), &nameSize, &displacement);
        if (SUCCEEDED(hr) && nameBuf[0] != 0) fullName = nameBuf;
    }

    Symbol sym;
    sym.address = addr - static_cast<Address>(displacement);
    sym.type = SymbolType::Function;

    // Split "module!function" into module and function parts
    auto bangPos = fullName.find('!');
    if (bangPos != std::string::npos) {
        sym.moduleName = fullName.substr(0, bangPos);
        sym.name = fullName.substr(bangPos + 1);
    } else {
        sym.name = fullName;
    }

    return sym;
}

// A pattern without a module would have the engine load every module's
// symbols to match it, which SYMOPT_NO_UNQUALIFIED_LOADS does not stop, so it
// is matched in each module that has its symbols already.
void DbgEngSymbolBackend::enumerateSymbols(const std::string& pattern, SymbolCallback callback) {
    if (!symbols || !callback) return;
    if (pattern.find('!') != std::string::npos) {
        matchSymbols(pattern, callback);
        return;
    }
    for (const auto& module : modulesWithSymbols())
        if (!matchSymbols(module + "!" + pattern, callback)) return;
}

std::optional<Symbol> DbgEngSymbolBackend::getSymbolWithExtent(Address addr) {
    auto sym = getSymbolByAddress(addr);
    if (!sym) return sym;

    // Asked at the symbol's start: from inside it the engine reports no size.
    DEBUG_MODULE_AND_ID id = {};
    HRESULT hr = symbols->GetSymbolEntriesByOffset(
        static_cast<ULONG64>(sym->address), 0, &id, nullptr, 1, nullptr);
    if (SUCCEEDED(hr)) {
        DEBUG_SYMBOL_ENTRY entry = {};
        entry.Size = sizeof(entry);
        hr = symbols->GetSymbolEntryInformation(&id, &entry);
        if (SUCCEEDED(hr)) sym->size = entry.Size;
    }
    return sym;
}

// The engine's name for the module at `base`, which a type name carries so it
// can be looked up again.
static std::string moduleShortName(IDebugSymbols3* symbols, ULONG64 base) {
    char buf[128] = {};
    ULONG index = 0;
    if (FAILED(symbols->GetModuleByOffset(base, 0, &index, nullptr))) return {};
    if (FAILED(symbols->GetModuleNameString(DEBUG_MODNAME_MODULE, index, 0,
                                            buf, sizeof(buf), nullptr)))
        return {};
    return buf;
}

std::optional<std::string> DbgEngSymbolBackend::getVariableTypeName(
    const std::string& name) {
    if (!symbols || name.empty()) return std::nullopt;

    auto known = variableTypeCache.find(name);
    if (known != variableTypeCache.end()) return known->second;

    std::optional<std::string> answer = lookUpVariableTypeName(name);
    variableTypeCache.emplace(name, answer);
    return answer;
}

std::optional<std::string> DbgEngSymbolBackend::lookUpVariableTypeName(
    const std::string& name) {
    ULONG typeId = 0;
    ULONG64 module = 0;
    if (FAILED(symbols->GetSymbolTypeId(name.c_str(), &typeId, &module)))
        return std::nullopt;

    char typeName[512] = {};
    if (FAILED(symbols->GetTypeName(module, typeId, typeName, sizeof(typeName),
                                    nullptr)))
        return std::nullopt;
    if (!typeName[0]) return std::nullopt;

    std::string shortName = moduleShortName(symbols, module);
    return shortName.empty() ? std::string(typeName)
                             : shortName + "!" + typeName;
}

const NativeTypeInfo* DbgEngSymbolBackend::getTypeByName(const std::string& name) {
    auto known = typeCache.find(name);
    if (known != typeCache.end())
        return known->second ? &*known->second : nullptr;
    if (!symbols || name.empty()) return nullptr;

    ULONG typeId = 0;
    ULONG64 module = 0;
    if (FAILED(symbols->GetSymbolTypeId(name.c_str(), &typeId, &module))) {
        typeCache.emplace(name, std::nullopt);
        return nullptr;
    }

    NativeTypeInfo info;
    info.name = name;

    ULONG size = 0;
    if (SUCCEEDED(symbols->GetTypeSize(module, typeId, &size))) info.size = size;

    // The engine cannot say how many fields there are: ask for each in turn
    // until there is no such index.
    for (ULONG index = 0; index < 4096; ++index) {
        char fieldName[512] = {};
        if (FAILED(symbols->GetFieldName(module, typeId, index, fieldName,
                                         sizeof(fieldName), nullptr)))
            break;
        if (!fieldName[0]) break;

        NativeField field;
        field.name = fieldName;

        ULONG fieldTypeId = 0, offset = 0;
        if (SUCCEEDED(symbols->GetFieldTypeAndOffset(module, typeId, fieldName,
                                                     &fieldTypeId, &offset))) {
            field.offset = offset;
            ULONG fieldSize = 0;
            if (SUCCEEDED(symbols->GetTypeSize(module, fieldTypeId, &fieldSize)))
                field.size = fieldSize;
            char fieldType[512] = {};
            if (SUCCEEDED(symbols->GetTypeName(module, fieldTypeId, fieldType,
                                               sizeof(fieldType), nullptr)))
                field.typeName = fieldType;
        }
        info.fields.push_back(std::move(field));
    }

    // Only a type with fields is described; anything else is Unknown.
    info.kind = info.fields.empty() ? NativeTypeKind::Unknown
                                    : NativeTypeKind::Struct;

    auto added = typeCache.emplace(name, std::move(info));
    return &*added.first->second;
}

std::vector<std::string> DbgEngSymbolBackend::modulesWithSymbols() {
    std::vector<std::string> names;
    ULONG loaded = 0, unloaded = 0;
    if (FAILED(symbols->GetNumberModules(&loaded, &unloaded))) return names;

    for (ULONG i = 0; i < loaded; i++) {
        DEBUG_MODULE_PARAMETERS params = {};
        if (FAILED(symbols->GetModuleParameters(1, nullptr, i, &params))) continue;
        if (params.SymbolType == DEBUG_SYMTYPE_DEFERRED
            || params.SymbolType == DEBUG_SYMTYPE_NONE)
            continue;

        char name[256] = {};
        if (SUCCEEDED(symbols->GetModuleNames(i, 0, nullptr, 0, nullptr, name, sizeof(name),
                                              nullptr, nullptr, 0, nullptr)))
            names.push_back(name);
    }
    return names;
}

bool DbgEngSymbolBackend::matchSymbols(const std::string& pattern,
                                       const SymbolCallback& callback) {
    ULONG64 handle = 0;
    if (FAILED(symbols->StartSymbolMatch(pattern.c_str(), &handle))) return true;

    char nameBuf[512] = {};
    ULONG64 offset = 0;
    while (SUCCEEDED(symbols->GetNextSymbolMatch(handle, nameBuf, sizeof(nameBuf), nullptr, &offset))) {
        Symbol sym;
        sym.address = static_cast<Address>(offset);
        sym.type = SymbolType::Function;

        std::string fullName = nameBuf;
        auto bangPos = fullName.find('!');
        if (bangPos != std::string::npos) {
            sym.moduleName = fullName.substr(0, bangPos);
            sym.name = fullName.substr(bangPos + 1);
        } else {
            sym.name = fullName;
        }

        if (!callback(sym)) {
            symbols->EndSymbolMatch(handle);
            return false;
        }
    }

    symbols->EndSymbolMatch(handle);
    return true;
}

static const char* symbolTypeName(ULONG type) {
    switch (type) {
        case DEBUG_SYMTYPE_NONE:     return "none";
        case DEBUG_SYMTYPE_COFF:     return "coff";
        case DEBUG_SYMTYPE_CODEVIEW: return "codeview";
        case DEBUG_SYMTYPE_PDB:      return "pdb";
        case DEBUG_SYMTYPE_EXPORT:   return "export";
        case DEBUG_SYMTYPE_DEFERRED: return "deferred";
        case DEBUG_SYMTYPE_SYM:      return "sym";
        case DEBUG_SYMTYPE_DIA:      return "dia";
        default:                     return "unknown";
    }
}

void DbgEngSymbolBackend::enumerateModules(ModuleCallback callback) {
    if (!symbols || !callback) return;

    ULONG loaded = 0, unloaded = 0;
    if (FAILED(symbols->GetNumberModules(&loaded, &unloaded))) return;

    for (ULONG i = 0; i < loaded; ++i) {
        DEBUG_MODULE_PARAMETERS params = {};
        if (FAILED(symbols->GetModuleParameters(1, nullptr, i, &params)))
            continue;

        char nameBuf[512] = {};
        symbols->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, 0,
                                     nameBuf, sizeof(nameBuf), nullptr);
        char shortBuf[256] = {};
        symbols->GetModuleNameString(DEBUG_MODNAME_MODULE, i, 0,
                                     shortBuf, sizeof(shortBuf), nullptr);

        // The symbol file the engine settled on — for a loaded PDB this is the
        // full path of the .pdb, which is what tells a mismatched/stale PDB
        // apart from the intended one.
        char symFileBuf[512] = {};
        symbols->GetModuleNameString(DEBUG_MODNAME_SYMBOL_FILE, i, 0,
                                     symFileBuf, sizeof(symFileBuf), nullptr);

        ModuleInfo info;
        info.path = nameBuf;
        info.shortName = shortBuf;
        info.symbolType = symbolTypeName(params.SymbolType);
        if (params.SymbolType != DEBUG_SYMTYPE_NONE &&
            params.SymbolType != DEBUG_SYMTYPE_DEFERRED)
            info.symbolFile = symFileBuf;
        info.loadAddress = static_cast<Address>(params.Base);
        info.endAddress  = static_cast<Address>(params.Base + params.Size);
        info.symbolCount = static_cast<uint64_t>(params.SymbolType != DEBUG_SYMTYPE_NONE ? 1 : 0);

        if (!callback(info)) return;
    }
}

std::optional<SourceLocation> DbgEngSymbolBackend::getSourceLocation(Address addr) {
    if (!symbols) return std::nullopt;

    ULONG line = 0;
    char fileBuf[512] = {};
    ULONG fileSize = 0;
    ULONG64 displacement = 0;
    HRESULT hr = symbols->GetLineByOffset(
        static_cast<ULONG64>(addr),
        &line,
        fileBuf, sizeof(fileBuf), &fileSize,
        &displacement);
    if (FAILED(hr)) return std::nullopt;

    SourceLocation loc;
    loc.filename = fileBuf;
    loc.line = line;
    loc.column = 0;
    loc.address = addr;
    return loc;
}

// Returns one of a symbol group's texts for a symbol, or an empty text when
// the engine has none.
static std::string groupText(IDebugSymbolGroup2& group, ULONG index,
                             HRESULT (STDMETHODCALLTYPE IDebugSymbolGroup2::*get)(ULONG, PSTR, ULONG, PULONG)) {
    char buffer[512] = {};
    ULONG size = 0;
    if (FAILED((group.*get)(index, buffer, sizeof(buffer), &size))) return {};
    return buffer;
}

static LocalVariable scopeVariable(IDebugSymbolGroup2& group, ULONG index, const StackFrame& frame) {
    LocalVariable variable;
    variable.frame = &frame;
    variable.name = groupText(group, index, &IDebugSymbolGroup2::GetSymbolName);
    variable.typeName = groupText(group, index, &IDebugSymbolGroup2::GetSymbolTypeName);
    variable.valueText = groupText(group, index, &IDebugSymbolGroup2::GetSymbolValueText);
    DEBUG_SYMBOL_PARAMETERS parameters = {};
    if (SUCCEEDED(group.GetSymbolParameters(index, 1, &parameters)))
        variable.isArgument = (parameters.Flags & DEBUG_SYMBOL_IS_ARGUMENT) != 0;
    ULONG size = 0;
    if (SUCCEEDED(group.GetSymbolSize(index, &size))) variable.size = size;
    ULONG64 offset = 0;
    if (SUCCEEDED(group.GetSymbolOffset(index, &offset))) {
        variable.locationType = VariableLocation::Memory;
        variable.address = offset;
    }
    return variable;
}

void DbgEngSymbolBackend::readScopeVariables(StackFrame& frame) {
    IDebugSymbolGroup2* raw = nullptr;
    if (FAILED(symbols->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ARGUMENTS | DEBUG_SCOPE_GROUP_LOCALS,
                                             nullptr, &raw)))
        return;
    ComPtr<IDebugSymbolGroup2> group(raw);
    ULONG count = 0;
    if (FAILED(group->GetNumberSymbols(&count))) return;
    for (ULONG i = 0; i < count; i++)
        frame.localVariables.push_back(scopeVariable(*group, i, frame));
}

// The engine answers a frame's arguments and locals for the scope it is set
// to, and the scope is the engine's own, so the one it had is put back.
void DbgEngSymbolBackend::getLocalVariables(StackFrame* frame) {
    ULONG64 previousOffset = 0;
    DEBUG_STACK_FRAME previousFrame = {};
    bool hadScope = SUCCEEDED(symbols->GetScope(&previousOffset, &previousFrame, nullptr, 0));

    DEBUG_STACK_FRAME scope = {};
    scope.InstructionOffset = frame->ip();
    scope.FrameOffset = frame->fp();
    scope.StackOffset = frame->sp();
    if (FAILED(symbols->SetScope(frame->ip(), &scope, nullptr, 0))) return;
    readScopeVariables(*frame);
    if (hadScope) symbols->SetScope(previousOffset, &previousFrame, nullptr, 0);
}

} // namespace smalldbg
