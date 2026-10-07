#include "MethodParser.h"
#include <cctype>
#include <cstdlib>
#include <set>

namespace smalltalk {

static const BlockNode* findBlock(const std::vector<BlockNode>& blocks, int idx) {
    for (const auto& b : blocks) {
        if (b.index == idx) return &b;
        auto nested = findBlock(b.blocks, idx);
        if (nested) return nested;
    }
    return nullptr;
}

const BlockNode* MethodNode::blockAt(int blockIndex) const {
    return findBlock(blocks, blockIndex);
}

static int countBlocksRecursive(const std::vector<BlockNode>& blocks) {
    int count = 0;
    for (const auto& b : blocks) {
        count += 1 + countBlocksRecursive(b.blocks);
    }
    return count;
}

int MethodNode::totalBlockCount() const {
    return countBlocksRecursive(blocks);
}

// Adds to `found` the names from `names` that appear as identifiers between
// `from` and `to`, outside strings and comments.
static void scanForIdentifiers(const std::string& src, size_t from, size_t to,
                               const std::set<std::string>& names,
                               std::set<std::string>& found) {
    size_t pos = from;
    while (pos < to && pos < src.size()) {
        char c = src[pos];
        if (c == '"') {
            MethodParser::skipComment(src, pos);
        } else if (c == '\'') {
            MethodParser::skipString(src, pos);
        } else if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            std::string id = MethodParser::readIdentifier(src, pos);
            if (names.count(id))
                found.insert(id);
        } else {
            ++pos;
        }
    }
}

// Adds to `found` the names read inside blocks that are not inlined.
static void collectCapturedInBlocks(const std::vector<BlockNode>& blocks,
                                    const std::string& source,
                                    const std::set<std::string>& names,
                                    std::set<std::string>& found) {
    for (const auto& b : blocks) {
        if (!b.isInlined) {
            scanForIdentifiers(source, b.sourceOffset + 1, b.bodyEnd, names, found);
        }
        // A real block nested in an inlined one still captures from the method.
        collectCapturedInBlocks(b.blocks, source, names, found);
    }
}

std::vector<bool> MethodNode::capturedTemps(const std::string& source) const {
    std::vector<bool> result(temporaryNames.size(), false);
    if (temporaryNames.empty() || blocks.empty())
        return result;

    std::set<std::string> tempNameSet(temporaryNames.begin(), temporaryNames.end());
    std::set<std::string> captured;
    collectCapturedInBlocks(blocks, source, tempNameSet, captured);

    for (size_t i = 0; i < temporaryNames.size(); i++) {
        if (captured.count(temporaryNames[i]))
            result[i] = true;
    }
    return result;
}

bool MethodParser::isBinaryChar(char c) {
    static const char binChars[] = "+-*/\\~<>=@%|&!?,";
    for (const char* p = binChars; *p; ++p) {
        if (c == *p) return true;
    }
    return false;
}

void MethodParser::skipWhitespace(const std::string& src, size_t& pos) {
    while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' ||
           src[pos] == '\r' || src[pos] == '\n')) {
        ++pos;
    }
}

void MethodParser::skipComment(const std::string& src, size_t& pos) {
    if (pos >= src.size() || src[pos] != '"') return;
    ++pos; // skip opening "
    while (pos < src.size() && src[pos] != '"') {
        ++pos;
    }
    if (pos < src.size()) ++pos; // skip closing "
}

void MethodParser::skipWhitespaceAndComments(const std::string& src, size_t& pos) {
    while (pos < src.size()) {
        skipWhitespace(src, pos);
        if (pos < src.size() && src[pos] == '"') {
            skipComment(src, pos);
        } else {
            break;
        }
    }
}

std::string MethodParser::readIdentifier(const std::string& src, size_t& pos) {
    size_t start = pos;
    if (pos < src.size() && (std::isalpha(static_cast<unsigned char>(src[pos])) || src[pos] == '_')) {
        ++pos;
        while (pos < src.size() && (std::isalnum(static_cast<unsigned char>(src[pos])) || src[pos] == '_')) {
            ++pos;
        }
    }
    return src.substr(start, pos - start);
}

std::string MethodParser::readBinarySelector(const std::string& src, size_t& pos) {
    size_t start = pos;
    while (pos < src.size() && isBinaryChar(src[pos])) {
        ++pos;
    }
    return src.substr(start, pos - start);
}

std::vector<std::string> MethodParser::parseTemporaries(const std::string& src, size_t& pos) {
    std::vector<std::string> temps;
    skipWhitespaceAndComments(src, pos);
    if (pos >= src.size() || src[pos] != '|') return temps;

    ++pos; // skip opening |
    while (pos < src.size()) {
        skipWhitespaceAndComments(src, pos);
        if (pos >= src.size()) break;
        if (src[pos] == '|') {
            ++pos; // skip closing |
            break;
        }
        std::string name = readIdentifier(src, pos);
        if (name.empty()) break; // malformed
        temps.push_back(name);
    }
    return temps;
}

void MethodParser::skipString(const std::string& src, size_t& pos) {
    if (pos >= src.size() || src[pos] != '\'') return;
    ++pos; // skip opening '
    while (pos < src.size()) {
        if (src[pos] == '\'') {
            ++pos;
            if (pos < src.size() && src[pos] == '\'') {
                ++pos; // escaped quote
                continue;
            }
            return; // end of string
        }
        ++pos;
    }
}

static void parseBlocksRecursive(const std::string& src, size_t pos,
                                  int& counter,
                                  std::vector<BlockNode>& out) {
    while (pos < src.size()) {
        char c = src[pos];
        if (c == '"') {
            MethodParser::skipComment(src, pos);
        } else if (c == '\'') {
            MethodParser::skipString(src, pos);
        } else if (c == '[') {
            BlockNode node;
            node.sourceOffset = pos; // position of '['
            ++pos; // skip [
            node.index = ++counter;

            // Parse block arguments: [:arg1 :arg2 | ...]
            MethodParser::skipWhitespaceAndComments(src, pos);
            if (pos < src.size() && src[pos] == ':') {
                while (pos < src.size() && src[pos] == ':') {
                    ++pos; // skip :
                    auto name = MethodParser::readIdentifier(src, pos);
                    if (!name.empty()) node.argumentNames.push_back(name);
                    MethodParser::skipWhitespaceAndComments(src, pos);
                }
                if (pos < src.size() && src[pos] == '|') ++pos; // skip |
            }

            // Parse block temporaries: | t1 t2 |
            node.temporaryNames = MethodParser::parseTemporaries(src, pos);

            // Recurse for nested blocks within this block body
            // Scan until matching ']', collecting nested blocks
            size_t bodyStart = pos;
            int depth = 1;
            size_t bodyEnd = pos;
            while (bodyEnd < src.size() && depth > 0) {
                char bc = src[bodyEnd];
                if (bc == '"') {
                    MethodParser::skipComment(src, bodyEnd);
                } else if (bc == '\'') {
                    MethodParser::skipString(src, bodyEnd);
                } else if (bc == '[') {
                    ++depth;
                    ++bodyEnd;
                } else if (bc == ']') {
                    --depth;
                    if (depth > 0) ++bodyEnd;
                } else {
                    ++bodyEnd;
                }
            }
            // Parse nested blocks inside this block's body
            parseBlocksRecursive(src, bodyStart, counter, node.blocks);

            node.bodyEnd = bodyEnd;
            out.push_back(std::move(node));
            pos = (bodyEnd < src.size()) ? bodyEnd + 1 : bodyEnd; // skip ]
        } else if (c == ']') {
            break; // end of enclosing block
        } else {
            ++pos;
        }
    }
}

void MethodParser::parseBlocks(const std::string& src, size_t pos,
                                   std::vector<BlockNode>& blocks) {
    int counter = 0;
    parseBlocksRecursive(src, pos, counter, blocks);
}

// From the colon after `firstKeyword` on: each keyword and its argument. A word
// with no colon after it is where the body begins, so `pos` is left on it.
void MethodParser::readKeywordSelector(const std::string& src, size_t& pos,
                                       const std::string& firstKeyword,
                                       MethodNode& node) {
    std::string keyword = firstKeyword;
    for (;;) {
        node.selector += keyword + ":";
        ++pos; // skip :
        skipWhitespaceAndComments(src, pos);
        std::string argName = readIdentifier(src, pos);
        if (!argName.empty()) node.argumentNames.push_back(argName);

        skipWhitespaceAndComments(src, pos);
        if (pos >= src.size()) return;
        if (!std::isalpha(static_cast<unsigned char>(src[pos])) && src[pos] != '_') return;
        size_t start = pos;
        keyword = readIdentifier(src, pos);
        skipWhitespace(src, pos);
        if (pos >= src.size() || src[pos] != ':') {
            pos = start;
            return;
        }
    }
}

MethodNode MethodParser::parse(const std::string& source) {
    MethodNode info;
    if (source.empty()) return info;

    size_t pos = 0;
    skipWhitespaceAndComments(source, pos);
    if (pos >= source.size()) return info;

    char first = source[pos];

    if (isBinaryChar(first)) {
        // Binary message: e.g. "+ anObject"
        info.selector = readBinarySelector(source, pos);
        skipWhitespaceAndComments(source, pos);
        std::string argName = readIdentifier(source, pos);
        if (!argName.empty()) info.argumentNames.push_back(argName);
    } else if (std::isalpha(static_cast<unsigned char>(first)) || first == '_') {
        std::string firstWord = readIdentifier(source, pos);
        skipWhitespace(source, pos);
        if (pos < source.size() && source[pos] == ':')
            readKeywordSelector(source, pos, firstWord, info);
        else
            info.selector = firstWord;
    }

    info.temporaryNames = parseTemporaries(source, pos);
    parseBlocks(source, pos, info.blocks);

    return info;
}

} // namespace smalltalk
