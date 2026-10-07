#pragma once

#include <string>
#include <vector>

namespace smalltalk {

/** A block found in a method's source. **/
struct BlockNode {
    int index = 0;           // 1-based, in source order, nested blocks included
    size_t sourceOffset = 0; // position of its '['
    size_t bodyEnd = 0;      // position of its matching ']'
    // Set by whoever knows which blocks the compiler inlined, such as those of
    // ifTrue: and whileTrue:; the parser leaves it false.
    bool isInlined = false;
    std::vector<std::string> argumentNames;
    std::vector<std::string> temporaryNames;
    std::vector<BlockNode> blocks;  // nested blocks
};

/** What a method's source declares: its selector, arguments, temporaries and
 *  blocks. **/
struct MethodNode {
    std::string selector;
    std::vector<std::string> argumentNames;
    std::vector<std::string> temporaryNames;
    std::vector<BlockNode> blocks;

    /** The block with this 1-based index. Returns null when there is none. **/
    const BlockNode* blockAt(int blockIndex) const;

    /** Every block in the method, nested ones included. **/
    int totalBlockCount() const;

    /** For each temporary, whether a block that is not inlined reads it, which
     *  makes it live in a context rather than on the stack. A block counts as
     *  real until its isInlined flag is set. **/
    std::vector<bool> capturedTemps(const std::string& source) const;
};

/** Reads the declarations out of a Smalltalk method's source text.
 *
 *  The syntax it reads is the language's, so every dialect can name a
 *  method's arguments, temporaries and blocks with it. **/
class MethodParser {
public:
    /** Returns an empty method when the source is empty or cannot be parsed.
     **/
    static MethodNode parse(const std::string& source);

    // Token helpers, shared with the block scan.
    static void skipWhitespace(const std::string& src, size_t& pos);
    static void skipComment(const std::string& src, size_t& pos);
    static void skipWhitespaceAndComments(const std::string& src, size_t& pos);
    static void skipString(const std::string& src, size_t& pos);
    static std::string readIdentifier(const std::string& src, size_t& pos);
    static std::vector<std::string> parseTemporaries(const std::string& src, size_t& pos);

private:
    static bool isBinaryChar(char c);
    static std::string readBinarySelector(const std::string& src, size_t& pos);
    static void readKeywordSelector(const std::string& src, size_t& pos,
                                    const std::string& firstKeyword, MethodNode& node);
    static void parseBlocks(const std::string& src, size_t pos,
                            std::vector<BlockNode>& blocks);
};

} // namespace smalltalk
