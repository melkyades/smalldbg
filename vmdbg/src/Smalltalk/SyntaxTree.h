#pragma once

#include <string>
#include <vector>

namespace smalltalk {

/** A SyntaxNode is one node of a parsed method. Its positions are 0-based
 *  offsets into the source, both inclusive. **/
struct SyntaxNode {
    enum class Kind { Leaf, Block, Brace, Send, Cascade, Assignment };

    Kind kind{Kind::Leaf};
    size_t start{0};
    size_t end{0};
    std::string selector;          // for a Send
    int receiver{-1};              // node index: a Send's or a Cascade's receiver,
                                   // an Assignment's value
    std::vector<int> arguments;    // a Send's arguments
    std::vector<int> children;     // a Block's or Brace's statements, a Cascade's
                                   // messages, an Assignment's variable
    std::vector<std::string> argumentNames;   // a Block's
    std::vector<std::string> temporaryNames;  // a Block's
};

/** A SyntaxTree holds the statements of a method with every expression in
 *  them, so that each message send can be found in the source. **/
struct SyntaxTree {
    std::string selector;
    std::vector<std::string> argumentNames;
    std::vector<std::string> temporaryNames;
    std::vector<SyntaxNode> nodes;
    std::vector<int> statements;

    const SyntaxNode& at(int index) const { return nodes[static_cast<size_t>(index)]; }
    /** Returns true when the node sends a message, counting the blocks
     *  inside it. **/
    bool sendsMessages(int index) const;
};

/** Returns the parsed method: its pattern, temporaries and statements, with
 *  pragmas skipped. For a source that does not parse, returns what was read
 *  up to there. **/
SyntaxTree parseMethodSyntax(const std::string& source);

} // namespace smalltalk
