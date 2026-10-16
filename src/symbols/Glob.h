#pragma once

#include <cctype>

namespace smalldbg {

// Whether `text` matches `pattern`, where '*' stands for any run of
// characters and '?' for any one, ignoring case, the way a symbol engine
// matches "module!name" patterns.
inline bool globMatches(const char* pattern, const char* text) {
    for (; *pattern; ++pattern, ++text) {
        if (*pattern == '*') {
            for (const char* rest = text;; ++rest) {
                if (globMatches(pattern + 1, rest)) return true;
                if (!*rest) return false;
            }
        }
        if (!*text) return false;
        if (*pattern != '?'
            && std::tolower(static_cast<unsigned char>(*pattern))
               != std::tolower(static_cast<unsigned char>(*text)))
            return false;
    }
    return !*text;
}

} // namespace smalldbg
