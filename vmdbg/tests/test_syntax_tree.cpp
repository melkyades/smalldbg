#include <doctest/doctest.h>

#include "Smalltalk/SyntaxTree.h"

#include <string>
#include <vector>

using smalltalk::SyntaxNode;
using smalltalk::SyntaxTree;

namespace {

// Returns the selectors the tree sends, in the order its nodes were made:
// innermost first, so a receiver's sends come before the send to it.
std::vector<std::string> selectorsOf(const SyntaxTree& tree) {
    std::vector<std::string> selectors;
    for (const auto& node : tree.nodes)
        if (node.kind == SyntaxNode::Kind::Send) selectors.push_back(node.selector);
    return selectors;
}

std::string textOf(const std::string& source, const SyntaxNode& node) {
    return source.substr(node.start, node.end - node.start + 1);
}

} // namespace

TEST_CASE("a method's sends are found with their place in the source") {
    std::string source = "at: i put: x\n\t| old |\n\told := self at: i.\n\t^old + (x max: 0)";
    SyntaxTree tree = smalltalk::parseMethodSyntax(source);
    CHECK(selectorsOf(tree) == std::vector<std::string>{"at:", "max:", "+"});
    REQUIRE(tree.statements.size() == 2);

    const SyntaxNode& assignment = tree.at(tree.statements[0]);
    CHECK(assignment.kind == SyntaxNode::Kind::Assignment);
    CHECK(textOf(source, tree.at(assignment.receiver)) == "self at: i");
    CHECK(textOf(source, tree.at(tree.statements[1])) == "old + (x max: 0)");
}

TEST_CASE("a method's pattern and temporaries are read with its statements") {
    SyntaxTree tree = smalltalk::parseMethodSyntax(
        "at: i put: x\n\t| old |\n\t^[:each | | seen | seen := each]");
    CHECK(tree.selector == "at:put:");
    CHECK(tree.argumentNames == std::vector<std::string>{"i", "x"});
    CHECK(tree.temporaryNames == std::vector<std::string>{"old"});
    REQUIRE(tree.statements.size() == 1);
    const SyntaxNode& block = tree.at(tree.statements[0]);
    CHECK(block.argumentNames == std::vector<std::string>{"each"});
    CHECK(block.temporaryNames == std::vector<std::string>{"seen"});
}

TEST_CASE("pragmas and temporaries are not taken for statements") {
    SyntaxTree tree = smalltalk::parseMethodSyntax(
        "primAt: i\n\t<primitive: 60>\n\t| a |\n\t^self error: 'bad'");
    REQUIRE(tree.statements.size() == 1);
    CHECK(selectorsOf(tree) == std::vector<std::string>{"error:"});
}

TEST_CASE("a cascade sends each of its messages to one receiver") {
    std::string source = "run\n\tstream nextPutAll: 'a'; cr; flush";
    SyntaxTree tree = smalltalk::parseMethodSyntax(source);
    REQUIRE(tree.statements.size() == 1);
    const SyntaxNode& cascade = tree.at(tree.statements[0]);
    CHECK(cascade.kind == SyntaxNode::Kind::Cascade);
    CHECK(cascade.children.size() == 3);
    CHECK(selectorsOf(tree) == std::vector<std::string>{"nextPutAll:", "cr", "flush"});
}

TEST_CASE("only a node with a send in it sends messages") {
    SyntaxTree tree = smalltalk::parseMethodSyntax("run\n\t[:x | x] value: 3. [42]");
    REQUIRE(tree.statements.size() == 2);
    CHECK(tree.sendsMessages(tree.statements[0]));
    CHECK_FALSE(tree.sendsMessages(tree.statements[1]));
}
