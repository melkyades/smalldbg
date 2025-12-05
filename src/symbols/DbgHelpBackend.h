// DbgHelp symbol backend for Windows
#pragma once

#include "../../include/smalldbg/SymbolBackend.h"
#include "../../include/smalldbg/SymbolProvider.h"
#include <windows.h>
#include <string>

namespace smalldbg {

class DbgHelpBackend : public SymbolBackend {
public:
    DbgHelpBackend();
    ~DbgHelpBackend() override;

    // Options
    void setOptions(const SymbolOptions& options) override { symbolOptions = options; }

    // Initialization
    Status initialize(void* processHandle, const SymbolOptions& options) override;
    void shutdown() override;
    
    // Symbol lookup
    std::optional<Symbol> getSymbolByName(const std::string& name) override;
    std::optional<Symbol> getSymbolByAddress(Address addr) override;
    
    // Source/line information
    std::optional<SourceLocation> getSourceLocation(Address addr) override;
    
    // Status
    bool isInitialized() const override { return initialized; }
    
    // Called by backend when a module is loaded
    void registerModule(HANDLE fileHandle, void* baseAddress, const std::string& imageName, DWORD imageSize);

private:
    // CodeView debug info structure for PDB 7.0
    struct CV_INFO_PDB70 {
        DWORD Signature;  // 0x53445352 'RSDS'
        GUID Guid;
        DWORD Age;
        char PdbFileName[1];
    };
    
    // Symbol server helpers
    void tryFetchPdbForModule(void* baseAddress, const std::string& imageName);
    bool readCodeViewInfo(void* baseAddress, CV_INFO_PDB70** outCvInfo, std::vector<char>& cvDataStorage);
    bool tryDownloadWithSymFindFile(const CV_INFO_PDB70* cvInfo);
    bool tryDownloadWithHTTP(const char* pdbName, const char* signature);
    void addPdbDirectoryToSearchPath(const std::string& pdbDir);
    std::string buildSymbolSearchPath();
    
    HANDLE processHandle{NULL};
    bool initialized{false};
    SymbolOptions symbolOptions;
    std::string symbolSearchPath;
    std::vector<std::string> downloadedPdbDirs;  // Track directories of downloaded PDBs
};

} // namespace smalldbg
