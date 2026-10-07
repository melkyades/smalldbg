#include <doctest/doctest.h>

#include "Smalltalk/MethodParser.h"

#include <string>
#include <vector>

using smalltalk::MethodNode;
using smalltalk::MethodParser;
using Names = std::vector<std::string>;

TEST_CASE("a method header gives its selector and arguments") {
    MethodNode unary = MethodParser::parse("size\n\t^tally");
    CHECK(unary.selector == "size");
    CHECK(unary.argumentNames.empty());

    MethodNode binary = MethodParser::parse("+ aNumber\n\t^self add: aNumber");
    CHECK(binary.selector == "+");
    CHECK(binary.argumentNames == Names{"aNumber"});

    MethodNode keyword = MethodParser::parse("at: index put: value\n\t^self basicAt: index put: value");
    CHECK(keyword.selector == "at:put:");
    CHECK(keyword.argumentNames == Names{"index", "value"});
}

TEST_CASE("a comment before or inside the header is skipped") {
    MethodNode node = MethodParser::parse("\"leading\" at: \"key\" key ifAbsent: aBlock\n\t^nil");
    CHECK(node.selector == "at:ifAbsent:");
    CHECK(node.argumentNames == Names{"key", "aBlock"});
}

TEST_CASE("a keyword send in the body is not part of the selector") {
    MethodNode node = MethodParser::parse("printOn: aStream\n\taStream nextPutAll: 'x'");
    CHECK(node.selector == "printOn:");
    CHECK(node.argumentNames == Names{"aStream"});
}

TEST_CASE("temporaries follow the header") {
    MethodNode node = MethodParser::parse("sum\n\t| total each |\n\ttotal := 0.\n\t^total");
    CHECK(node.temporaryNames == Names{"total", "each"});
}

TEST_CASE("blocks are numbered in source order, nested ones included") {
    std::string source =
        "do: aBlock\n"
        "\t| count |\n"
        "\tself items do: [:each | | doubled | doubled := each * 2. [:x | x] value: doubled].\n"
        "\t^[count]";
    MethodNode node = MethodParser::parse(source);

    REQUIRE(node.totalBlockCount() == 3);
    REQUIRE(node.blockAt(1) != nullptr);
    CHECK(node.blockAt(1)->argumentNames == Names{"each"});
    CHECK(node.blockAt(1)->temporaryNames == Names{"doubled"});
    REQUIRE(node.blockAt(2) != nullptr);
    CHECK(node.blockAt(2)->argumentNames == Names{"x"});
    REQUIRE(node.blockAt(3) != nullptr);
    CHECK(node.blockAt(3)->argumentNames.empty());
    CHECK(node.blockAt(4) == nullptr);
}

TEST_CASE("brackets inside strings and comments are not blocks") {
    MethodNode node = MethodParser::parse("label\n\t\"a [comment]\"\n\t^'[not a block]'");
    CHECK(node.totalBlockCount() == 0);
}

TEST_CASE("a temporary is captured when a real block reads it") {
    std::string source =
        "run\n"
        "\t| kept free |\n"
        "\tfree := 1.\n"
        "\t^[kept]";
    MethodNode node = MethodParser::parse(source);
    CHECK(node.capturedTemps(source) == std::vector<bool>{true, false});

    node.blocks[0].isInlined = true;
    CHECK(node.capturedTemps(source) == std::vector<bool>{false, false});
}

TEST_CASE("empty source parses to an empty method") {
    MethodNode node = MethodParser::parse("");
    CHECK(node.selector.empty());
    CHECK(node.totalBlockCount() == 0);
}
