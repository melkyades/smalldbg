// macOS source-location resolution via `atos`.
#include "../../SourceResolver.h"
#include <cstdio>
#include <iostream>
#include <sys/stat.h>

namespace smalldbg {

static std::string shellEscape(const std::string& s) {
    std::string result = "'";
    for (char c : s) {
        if (c == '\'') result += "'\\''";
        else result += c;
    }
    result += "'";
    return result;
}

std::optional<SourceLocation> resolveSourceLocation(
    const std::string& binaryPath, uint64_t loadAddress, Address addr) {

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "atos -fullPath -o %s -l 0x%llx 0x%llx 2>/dev/null",
             shellEscape(binaryPath).c_str(),
             static_cast<unsigned long long>(loadAddress),
             static_cast<unsigned long long>(addr));

    FILE* pipe = popen(cmd, "r");
    if (!pipe) return std::nullopt;

    char buf[4096];
    std::string output;
    while (fgets(buf, sizeof(buf), pipe))
        output += buf;
    pclose(pipe);

    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();

    // atos output: "function (in module) (file:line)"
    // The last parenthesized group contains file:line when source info exists
    auto lastClose = output.rfind(')');
    if (lastClose == std::string::npos) return std::nullopt;

    auto lastOpen = output.rfind('(', lastClose);
    if (lastOpen == std::string::npos) return std::nullopt;

    std::string inner = output.substr(lastOpen + 1, lastClose - lastOpen - 1);

    // Skip "(in moduleName)" — not a source location
    if (inner.size() > 3 && inner.compare(0, 3, "in ") == 0) return std::nullopt;

    auto colon = inner.rfind(':');
    if (colon == std::string::npos || colon == 0) return std::nullopt;

    SourceLocation loc;
    loc.filename = inner.substr(0, colon);
    loc.address = addr;
    try { loc.line = static_cast<uint32_t>(std::stoul(inner.substr(colon + 1))); }
    catch (...) { return std::nullopt; }

    // Check if file exists; if not, log for debugging
    struct stat st;
    if (stat(loc.filename.c_str(), &st) != 0) {
        std::cerr << "[atos] source file not found: " << loc.filename << std::endl;
    }

    return loc;
}

} // namespace smalldbg
