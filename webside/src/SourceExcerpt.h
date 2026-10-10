#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace webside {

/** A SourceExcerpt is the text of the function that holds a line of a source
 *  file in a language with braces, such as C++, and where that line is in the
 *  text. **/
struct SourceExcerpt {
    std::string text;
    int lineStart{0};    // character offset of the line within the text
    int lineLength{0};
};

/** Returns the function in the file at `path` that holds line `line`,
 *  counted from 1, from its signature to its closing brace. Returns nothing
 *  when the file cannot be read or the line is inside no braces. **/
std::optional<SourceExcerpt> functionAround(const std::string& path,
                                            uint32_t line);

} // namespace webside
