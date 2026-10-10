#include "MethodParser.h"
#include "SyntaxTree.h"

#include <algorithm>
#include <utility>

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

// Adds to `ranges` where each block that is not inlined runs, between its
// brackets. A real block nested in an inlined one still captures from the
// method.
static void realBlockRanges(const std::vector<BlockNode>& blocks,
                            std::vector<std::pair<size_t, size_t>>& ranges) {
    for (const auto& b : blocks) {
        if (!b.isInlined) ranges.emplace_back(b.sourceOffset, b.bodyEnd);
        realBlockRanges(b.blocks, ranges);
    }
}

std::vector<bool> MethodNode::capturedTemps(const std::string& source) const {
    std::vector<bool> result(temporaryNames.size(), false);
    if (temporaryNames.empty() || blocks.empty())
        return result;

    std::vector<std::pair<size_t, size_t>> ranges;
    realBlockRanges(blocks, ranges);
    SyntaxTree tree = parseMethodSyntax(source);
    for (const auto& node : tree.nodes) {
        if (node.kind != SyntaxNode::Kind::Leaf) continue;
        bool inRealBlock = std::any_of(ranges.begin(), ranges.end(), [&](const auto& range) {
            return node.start > range.first && node.end < range.second;
        });
        if (!inRealBlock) continue;
        std::string name = source.substr(node.start, node.end - node.start + 1);
        for (size_t i = 0; i < temporaryNames.size(); i++) {
            if (temporaryNames[i] == name) result[i] = true;
        }
    }
    return result;
}

namespace {

// Adds to `out` the blocks under node `index`, each with the blocks inside it.
// A cascade's receiver is its first message's, so it is visited through that.
void collectBlocks(const SyntaxTree& tree, int index, std::vector<BlockNode>& out) {
    if (index < 0) return;
    const SyntaxNode& node = tree.at(index);
    if (node.kind == SyntaxNode::Kind::Block) {
        BlockNode block;
        block.sourceOffset = node.start;
        block.bodyEnd = node.end;
        block.argumentNames = node.argumentNames;
        block.temporaryNames = node.temporaryNames;
        for (int child : node.children) collectBlocks(tree, child, block.blocks);
        out.push_back(std::move(block));
        return;
    }
    if (node.kind != SyntaxNode::Kind::Cascade) collectBlocks(tree, node.receiver, out);
    for (int argument : node.arguments) collectBlocks(tree, argument, out);
    for (int child : node.children) collectBlocks(tree, child, out);
}

// Numbers the blocks in the order their brackets open.
void numberBlocks(std::vector<BlockNode>& blocks, int& counter) {
    std::sort(blocks.begin(), blocks.end(), [](const BlockNode& a, const BlockNode& b) {
        return a.sourceOffset < b.sourceOffset;
    });
    for (auto& block : blocks) {
        block.index = ++counter;
        numberBlocks(block.blocks, counter);
    }
}

} // namespace

MethodNode MethodParser::parse(const std::string& source) {
    SyntaxTree tree = parseMethodSyntax(source);
    MethodNode method;
    method.selector = tree.selector;
    method.argumentNames = tree.argumentNames;
    method.temporaryNames = tree.temporaryNames;
    for (int statement : tree.statements) collectBlocks(tree, statement, method.blocks);
    int counter = 0;
    numberBlocks(method.blocks, counter);
    return method;
}

} // namespace smalltalk
