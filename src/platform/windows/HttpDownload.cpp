#include "HttpDownload.h"
#include <windows.h>
#include <winhttp.h>
#include <filesystem>
#include <cstdio>

#pragma comment(lib, "winhttp.lib")

namespace smalldbg {
namespace platform {

bool downloadFileHTTP(const char* url, const char* localPath) {
    // Parse URL to extract components
    wchar_t wideUrl[2048];
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wideUrl, 2048);
    
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256], urlPath[1024];
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;
    
    if (!WinHttpCrackUrl(wideUrl, 0, 0, &urlComp)) {
        return false;
    }
    
    // Open session
    HINTERNET hSession = WinHttpOpen(
        L"SmallDbg/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    if (!hSession) {
        return false;
    }
    
    // Connect to server
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        hostName,
        urlComp.nPort,
        0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Open request
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        urlPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &statusCode,
        &statusCodeSize,
        NULL);
    
    if (statusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Create directory if needed
    std::filesystem::path filePath(localPath);
    std::filesystem::path dirPath = filePath.parent_path();
    if (!dirPath.empty()) {
        std::filesystem::create_directories(dirPath);
    }
    
    // Open local file
    FILE* file = nullptr;
    if (fopen_s(&file, localPath, "wb") != 0 || !file) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Read and write data
    DWORD bytesRead = 0;
    BYTE buffer[4096];
    bool success = true;
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (fwrite(buffer, 1, bytesRead, file) != bytesRead) {
            success = false;
            break;
        }
    }
    
    fclose(file);
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return success;
}

} // namespace platform
} // namespace smalldbg
