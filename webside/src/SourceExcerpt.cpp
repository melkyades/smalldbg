#include "SourceExcerpt.h"

#include <fstream>
#include <vector>

namespace webside {

namespace {

std::vector<std::string> linesOf(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) lines.push_back(line);
    return lines;
}

// Returns the innermost brace that opens before `line` and is still open
// there.
int openingBrace(const std::vector<std::string>& lines, int line) {
    int depth = 0;
    for (int i = line; i >= 0; i--) {
        const auto& text = lines[i];
        for (int j = static_cast<int>(text.size()) - 1; j >= 0; j--) {
            if (text[j] == '}') depth++;
            else if (text[j] == '{') {
                if (depth == 0) return i;
                depth--;
            }
        }
    }
    return -1;
}

// A signature runs back from its brace to a blank line, a closing brace or a
// preprocessor line.
int signatureStart(const std::vector<std::string>& lines, int braceLine) {
    int start = braceLine;
    for (int i = braceLine - 1; i >= 0; i--) {
        auto first = lines[i].find_first_not_of(" \t");
        if (first == std::string::npos) break;
        char c = lines[i][first];
        if (c == '}' || c == '#') break;
        start = i;
    }
    return start;
}

int closingBrace(const std::vector<std::string>& lines, int braceLine) {
    int depth = 0;
    for (int i = braceLine; i < static_cast<int>(lines.size()); i++) {
        for (char c : lines[i]) {
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
    }
    return -1;
}

} // namespace

std::optional<SourceExcerpt> functionAround(const std::string& path,
                                            uint32_t line) {
    const auto lines = linesOf(path);
    if (line == 0 || line > lines.size()) return std::nullopt;
    const int target = static_cast<int>(line) - 1;
    const int open = openingBrace(lines, target);
    if (open < 0) return std::nullopt;
    const int close = closingBrace(lines, open);
    if (close < 0) return std::nullopt;

    SourceExcerpt excerpt;
    for (int i = signatureStart(lines, open); i <= close; i++) {
        if (!excerpt.text.empty()) excerpt.text += '\n';
        if (i == target) {
            excerpt.lineStart = static_cast<int>(excerpt.text.size());
            excerpt.lineLength = static_cast<int>(lines[i].size());
        }
        excerpt.text += lines[i];
    }
    return excerpt;
}

} // namespace webside
