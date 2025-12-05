#include "DbgHelpBackend.h"
#include "../platform/windows/HttpDownload.h"
#include <DbgHelp.h>
#include <Psapi.h>
#include <algorithm>
#include <filesystem>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")

namespace smalldbg {

DbgHelpBackend::DbgHelpBackend() 
    : processHandle(NULL), initialized(false) {
}

DbgHelpBackend::~DbgHelpBackend() {
    shutdown();
}

Status DbgHelpBackend::initialize(void* procHandle, const SymbolOptions& options) {
    if (initialized) {
        return Status::AlreadyAttached;
    }
    
    processHandle = static_cast<HANDLE>(procHandle);
    symbolOptions = options;
    
    // Load symsrv.dll if using symbol server
    if (symbolOptions.useSymbolServer) {
        if (!LoadLibraryA("symsrv.dll")) {
            fprintf(stderr, "Warning: Failed to load symsrv.dll - symbol server will not work\n");
            fflush(stderr);
        }
    }
    
    // Configure symbol options
    DWORD symOpts = 0;
    if (symbolOptions.undecoratenames) {
        symOpts |= SYMOPT_UNDNAME;
    }
    if (symbolOptions.deferredLoading) {
        symOpts |= SYMOPT_DEFERRED_LOADS;
    }
    if (symbolOptions.loadLineInfo) {
        symOpts |= SYMOPT_LOAD_LINES;
    }
    if (symbolOptions.exactSymbols) {
        symOpts |= SYMOPT_EXACT_SYMBOLS;
    }
    if (symbolOptions.useSymbolServer) {
        symOpts |= SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS;
    }
    SymSetOptions(symOpts);
    
    // Build symbol search path
    std::string searchPath = buildSymbolSearchPath();
    symbolSearchPath = searchPath;
    
    // Initialize symbol handler
    if (!SymInitialize(processHandle, symbolSearchPath.c_str(), FALSE)) {
        return Status::Error;
    }
    
    initialized = true;
    return Status::Ok;
}

std::string DbgHelpBackend::buildSymbolSearchPath() {
    std::string path;
    
    // Custom search paths
    if (!symbolOptions.searchPath.empty()) {
        path = symbolOptions.searchPath;
    }
    
    // Current directory
    if (!path.empty()) path += ";";
    path += ".";
    
    // Executable directory
    char exePath[MAX_PATH];
    if (GetModuleFileNameExA(processHandle, NULL, exePath, sizeof(exePath))) {
        std::string exeDir = exePath;
        size_t lastSlash = exeDir.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            exeDir = exeDir.substr(0, lastSlash);
            if (!path.empty()) path += ";";
            path += exeDir;
        }
    }
    
    // Symbol server cache and URL
    if (symbolOptions.useSymbolServer) {
        if (!path.empty()) path += ";";
        path += symbolOptions.cacheDirectory;
        
        if (!path.empty()) path += ";";
        path += "SRV*" + symbolOptions.cacheDirectory + "*" + symbolOptions.symbolServerUrl;
    }
    
    return path;
}

void DbgHelpBackend::shutdown() {
    if (!initialized) return;
    
    SymCleanup(processHandle);
    processHandle = NULL;
    initialized = false;
}

// Extract PDB filename without path
static const char* extractPdbFileName(const char* fullPath) {
    const char* name = fullPath;
    const char* lastSlash = strrchr(name, '\\');
    if (lastSlash) name = lastSlash + 1;
    lastSlash = strrchr(name, '/');
    if (lastSlash) name = lastSlash + 1;
    return name;
}

// Build symbol server signature string from GUID and Age
static void buildSignatureString(const GUID& guid, DWORD age, char* output, size_t outputSize) {
    sprintf_s(output, outputSize, "%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7],
            age);
}

// Add PDB directory to search path if not already tracked
void DbgHelpBackend::addPdbDirectoryToSearchPath(const std::string& pdbDir) {
    if (std::find(downloadedPdbDirs.begin(), downloadedPdbDirs.end(), pdbDir) != downloadedPdbDirs.end()) {
        return;  // Already tracked
    }
    
    downloadedPdbDirs.push_back(pdbDir);
    
    // Rebuild search path with all PDB directories
    std::string newPath = symbolSearchPath;
    for (const auto& dir : downloadedPdbDirs) {
        newPath += ";" + dir;
    }
    SymSetSearchPath(processHandle, newPath.c_str());
    
    // Note: SymRefreshModuleList doesn't force deferred symbols to load
    // The actual loading will happen on-demand when symbols are accessed
    SymRefreshModuleList(processHandle);
}

// Try to download PDB using SymFindFileInPath (checks cache first)
bool DbgHelpBackend::tryDownloadWithSymFindFile(const CV_INFO_PDB70* cvInfo) {
    char pdbPath[MAX_PATH] = {0};
    BOOL found = SymFindFileInPath(
        processHandle, NULL, (PSTR)cvInfo->PdbFileName,
        (PVOID)&cvInfo->Guid, cvInfo->Age, 0,
        SSRVOPT_GUIDPTR, pdbPath, NULL, NULL);
    
    if (!found) return false;
    
    std::filesystem::path pdbFilePath(pdbPath);
    std::string pdbDir = pdbFilePath.parent_path().string();
    addPdbDirectoryToSearchPath(pdbDir);
    
    fprintf(stderr, "  Successfully loaded symbols from cache\n");
    fflush(stderr);
    return true;
}

// Try to download PDB via direct HTTP
bool DbgHelpBackend::tryDownloadWithHTTP(const char* pdbName, const char* signature) {
    // Build URL: server/pdbname/signature/pdbname
    char url[1024];
    sprintf_s(url, sizeof(url), "%s/%s/%s/%s",
            symbolOptions.symbolServerUrl.c_str(),
            pdbName, signature, pdbName);
    
    // Build local cache path
    char localPath[MAX_PATH];
    sprintf_s(localPath, sizeof(localPath), "%s\\%s\\%s\\%s",
            symbolOptions.cacheDirectory.c_str(),
            pdbName, signature, pdbName);
    
    if (!platform::downloadFileHTTP(url, localPath)) {
        fprintf(stderr, "  Failed to download symbols\n");
        fflush(stderr);
        return false;
    }
    
    std::filesystem::path pdbFilePath(localPath);
    std::string pdbDir = pdbFilePath.parent_path().string();
    addPdbDirectoryToSearchPath(pdbDir);
    
    fprintf(stderr, "  Downloaded and cached symbols\n");
    fflush(stderr);
    return true;
}

// Read CodeView debug info from PE file in target process
bool DbgHelpBackend::readCodeViewInfo(void* baseAddress, CV_INFO_PDB70** outCvInfo, std::vector<char>& cvDataStorage) {
    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle, baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead) ||
        bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    // Read NT headers
    IMAGE_NT_HEADERS64 ntHeaders;
    void* ntHeadersAddr = (char*)baseAddress + dosHeader.e_lfanew;
    if (!ReadProcessMemory(processHandle, ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead) ||
        bytesRead != sizeof(ntHeaders) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    // Get debug directory
    IMAGE_DATA_DIRECTORY debugDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDir.VirtualAddress == 0 || debugDir.Size == 0) {
        return false;
    }
    
    // Read debug directory entries
    void* debugDirAddr = (char*)baseAddress + debugDir.VirtualAddress;
    DWORD numEntries = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    std::vector<IMAGE_DEBUG_DIRECTORY> debugEntries(numEntries);
    
    if (!ReadProcessMemory(processHandle, debugDirAddr, debugEntries.data(),
                          debugDir.Size, &bytesRead) || bytesRead != debugDir.Size) {
        return false;
    }
    
    // Find CodeView entry
    for (DWORD i = 0; i < numEntries; i++) {
        if (debugEntries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW || debugEntries[i].SizeOfData == 0) {
            continue;
        }
        
        // Read CodeView data
        cvDataStorage.resize(debugEntries[i].SizeOfData);
        void* cvDataAddr = (char*)baseAddress + debugEntries[i].AddressOfRawData;
        
        if (!ReadProcessMemory(processHandle, cvDataAddr, cvDataStorage.data(),
                              debugEntries[i].SizeOfData, &bytesRead)) {
            return false;
        }
        
        DbgHelpBackend::CV_INFO_PDB70* cvInfo = (DbgHelpBackend::CV_INFO_PDB70*)cvDataStorage.data();
        if (cvInfo->Signature != 0x53445352) {  // 'RSDS'
            return false;
        }
        
        *outCvInfo = cvInfo;
        return true;
    }
    
    return false;
}

// Try to fetch and load PDB for a module
void DbgHelpBackend::tryFetchPdbForModule(void* baseAddress, const std::string& imageName) {
    // Read CodeView debug info from PE file
    DbgHelpBackend::CV_INFO_PDB70* cvInfo = nullptr;
    std::vector<char> cvDataStorage;
    
    if (!readCodeViewInfo(baseAddress, &cvInfo, cvDataStorage)) {
        return;  // No debug info available
    }
    
    // Build signature string
    char signature[64];
    buildSignatureString(cvInfo->Guid, cvInfo->Age, signature, sizeof(signature));
    
    // Extract PDB filename
    const char* pdbName = extractPdbFileName(cvInfo->PdbFileName);
    
    fprintf(stderr, "Downloading symbols for %s...\n", imageName.c_str());
    fflush(stderr);
    
    // Try SymFindFileInPath first (checks cache)
    if (tryDownloadWithSymFindFile(cvInfo)) {
        return;
    }
    
    // Fall back to direct HTTP download
    tryDownloadWithHTTP(pdbName, signature);
}

void DbgHelpBackend::onModuleLoaded(HANDLE fileHandle, void* baseAddress, const std::string& imageName, DWORD imageSize) {
    if (!initialized) {
        return;
    }
    
    // Load symbols for this module  
    DWORD64 loadedBase = SymLoadModuleEx(
        processHandle, fileHandle,
        imageName.empty() ? NULL : imageName.c_str(),
        NULL,  // Module name (let DbgHelp figure it out)
        (DWORD64)baseAddress, imageSize,
        NULL, 0
    );
    
    // Check if we should try to download PDB
    if (!symbolOptions.useSymbolServer || loadedBase == 0 || imageName.empty()) {
        return;
    }
    
    // Get module info to check if PDB is already loaded
    IMAGEHLP_MODULE64 modInfo = {};
    modInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(processHandle, (DWORD64)baseAddress, &modInfo)) {
        return;
    }
    
    // Only try to fetch PDB if we have exports/deferred symbols and no PDB loaded
    if ((modInfo.SymType == SymExport || modInfo.SymType == SymDeferred) && 
        modInfo.LoadedPdbName[0] == '\0') {
        tryFetchPdbForModule(baseAddress, imageName);
        
        // Force symbols to load immediately by enumerating (triggers deferred load)
        // This is necessary because with SYMOPT_DEFERRED_LOADS, symbols aren't loaded
        // until first access, which can cause SymFromAddr to fail intermittently
        auto callback = [](PSYMBOL_INFO, ULONG, PVOID) -> BOOL { return FALSE; }; // Stop after first symbol
        SymEnumSymbols(processHandle, (DWORD64)baseAddress, NULL, callback, NULL);
    }
}

std::optional<Symbol> DbgHelpBackend::getSymbolByName(const std::string& name) {
    if (!initialized) return std::nullopt;
    
    // Allocate buffer for symbol info
    const size_t bufferSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
    std::vector<char> buffer(bufferSize);
    SYMBOL_INFO* symInfo = reinterpret_cast<SYMBOL_INFO*>(buffer.data());
    symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfo->MaxNameLen = MAX_SYM_NAME;
    
    if (!SymFromName(processHandle, name.c_str(), symInfo)) {
        return std::nullopt;
    }
    
    Symbol symbol;
    symbol.name = symInfo->Name;
    symbol.address = symInfo->Address;
    symbol.size = symInfo->Size;
    
    // Get module name
    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(processHandle, symInfo->Address, &moduleInfo)) {
        symbol.moduleName = moduleInfo.ModuleName;
    }
    
    return symbol;
}

std::optional<Symbol> DbgHelpBackend::getSymbolByAddress(Address addr) {
    if (!initialized) return std::nullopt;
    
    // Allocate buffer for symbol info
    const size_t bufferSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
    std::vector<char> buffer(bufferSize);
    SYMBOL_INFO* symInfo = reinterpret_cast<SYMBOL_INFO*>(buffer.data());
    symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfo->MaxNameLen = MAX_SYM_NAME;
    
    DWORD64 displacement = 0;
    if (!SymFromAddr(processHandle, addr, &displacement, symInfo)) {
        // SymFromAddr failed - try to at least get module info
        IMAGEHLP_MODULE64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        if (SymGetModuleInfo64(processHandle, addr, &moduleInfo)) {
            // Return module info with offset from base
            Symbol symbol;
            symbol.name = "";  // No function name available
            symbol.address = moduleInfo.BaseOfImage;
            symbol.size = moduleInfo.ImageSize;
            symbol.moduleName = moduleInfo.ModuleName;
            return symbol;
        }
        return std::nullopt;
    }
    
    Symbol symbol;
    symbol.name = symInfo->Name;
    symbol.address = symInfo->Address;
    symbol.size = symInfo->Size;
    
    // Get module name
    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(processHandle, symInfo->Address, &moduleInfo)) {
        symbol.moduleName = moduleInfo.ModuleName;
    }
    
    return symbol;
}

std::optional<SourceLocation> DbgHelpBackend::getSourceLocation(Address addr) {
    if (!initialized) return std::nullopt;
    
    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD displacement = 0;
    
    if (!SymGetLineFromAddr64(processHandle, addr, &displacement, &line)) {
        return std::nullopt;
    }
    
    SourceLocation loc;
    loc.filename = line.FileName;
    loc.line = line.LineNumber;
    loc.column = 0;  // DbgHelp doesn't provide column info
    loc.address = line.Address;
    
    return loc;
}

} // namespace smalldbg
