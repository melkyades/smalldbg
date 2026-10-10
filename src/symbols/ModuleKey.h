#pragma once

#include <cctype>
#include <string>

namespace smalldbg {

// A module's file name without directory or extension, lowercased:
// "KERNEL32.DLL", "kernel32.dll" and "Kernel32" are one module.
inline std::string moduleKey(const std::string& name) {
    auto slash = name.find_last_of("\\/");
    std::string key = slash == std::string::npos ? name : name.substr(slash + 1);
    for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto dot = key.find_last_of('.');
    if (dot != std::string::npos && dot > 0) key.erase(dot);
    return key;
}

} // namespace smalldbg
