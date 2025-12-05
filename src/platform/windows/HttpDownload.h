#pragma once

#include <string>

namespace smalldbg {
namespace platform {

// Download a file from a URL using WinHTTP
// Returns true on success, false on failure
bool downloadFileHTTP(const char* url, const char* localPath);

} // namespace platform
} // namespace smalldbg
