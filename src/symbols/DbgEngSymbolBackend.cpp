// DbgEng symbol backend — implementation.
//
// Wraps IDebugSymbols3 methods (GetNameByOffset, GetModuleByOffset,
// GetLineByOffset, GetOffsetByName) to implement the SymbolBackend interface.

#include "DbgEngSymbolBackend.h"

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

Status DbgEngSymbolBackend::initialize(void* /*processHandle*/, const SymbolOptions& opts) {
    options = opts;
    if (!symbols) return Status::Error;

    // Configure symbol path if provided.
    if (!opts.searchPath.empty() || opts.useSymbolServer) {
        std::string symPath;

        // Get existing symbol path
        char existingPath[2048] = {};
        ULONG pathSize = 0;
        symbols->GetSymbolPath(existingPath, sizeof(existingPath), &pathSize);
        symPath = existingPath;

        // Append user search path
        if (!opts.searchPath.empty()) {
            if (!symPath.empty()) symPath += ";";
            symPath += opts.searchPath;
        }

        // Append symbol server
        if (opts.useSymbolServer) {
            std::string srv = "srv*";
            if (!opts.cacheDirectory.empty()) {
                srv += opts.cacheDirectory;
            }
            srv += "*" + opts.symbolServerUrl;
            if (symPath.find(srv) == std::string::npos) {
                if (!symPath.empty()) symPath += ";";
                symPath += srv;
            }
        }

        symbols->SetSymbolPath(symPath.c_str());
    }

    initialized = true;
    return Status::Ok;
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

    // Try to get symbol size via GetSymbolEntriesByOffset
    DEBUG_MODULE_AND_ID id = {};
    hr = symbols->GetSymbolEntriesByOffset(
        static_cast<ULONG64>(addr), 0, &id, nullptr, 1, nullptr);
    if (SUCCEEDED(hr)) {
        DEBUG_SYMBOL_ENTRY entry = {};
        entry.Size = sizeof(entry);
        hr = symbols->GetSymbolEntryInformation(&id, &entry);
        if (SUCCEEDED(hr)) {
            sym.size = entry.Size;
        }
    }

    return sym;
}

void DbgEngSymbolBackend::enumerateSymbols(const std::string& pattern, SymbolCallback callback) {
    if (!symbols || !callback) return;

    // Use IDebugSymbols3::StartSymbolMatch / GetNextSymbolMatch
    ULONG64 handle = 0;
    HRESULT hr = symbols->StartSymbolMatch(pattern.c_str(), &handle);
    if (FAILED(hr)) return;

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

        if (!callback(sym)) break;
    }

    symbols->EndSymbolMatch(handle);
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

void DbgEngSymbolBackend::getLocalVariables(StackFrame* /*frame*/) {
    // TODO: Implement via IDebugSymbolGroup2 or Execute("dv /t")
}

} // namespace smalldbg
