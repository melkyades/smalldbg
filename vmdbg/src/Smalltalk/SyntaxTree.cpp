#include "SyntaxTree.h"

#include <algorithm>
#include <cctype>

namespace smalltalk {

namespace {

enum class TokenKind { Identifier, Keyword, Binary, Literal, Assign, BlockArg, Special, End };

struct Token {
    TokenKind kind{TokenKind::End};
    std::string text;
    size_t start{0};
    size_t end{0};
};

bool isBinaryCharacter(char c) {
    return std::string("+-*/\\<>=~@%|&?,!").find(c) != std::string::npos;
}

bool isWordCharacter(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

class Tokenizer {
public:
    explicit Tokenizer(const std::string& text) : src(text) {}

    std::vector<Token> tokens() {
        std::vector<Token> out;
        while (skipSeparators()) out.push_back(next());
        return out;
    }

private:
    const std::string& src;
    size_t pos{0};

    char at(size_t i) const { return i < src.size() ? src[i] : '\0'; }

    // Skips blanks and comments; returns false at the end of the source.
    bool skipSeparators() {
        while (pos < src.size()) {
            char c = src[pos];
            if (std::isspace(static_cast<unsigned char>(c))) { pos++; continue; }
            if (c != '"') return true;
            size_t close = src.find('"', pos + 1);
            pos = close == std::string::npos ? src.size() : close + 1;
        }
        return false;
    }

    Token make(TokenKind kind, size_t start, size_t afterEnd) {
        pos = afterEnd;
        return {kind, src.substr(start, afterEnd - start), start, afterEnd - 1};
    }

    size_t wordEnd(size_t from) const {
        size_t i = from;
        while (i < src.size() && isWordCharacter(src[i])) i++;
        return i;
    }

    size_t binaryEnd(size_t from) const {
        size_t i = from;
        while (i < src.size() && isBinaryCharacter(src[i])) i++;
        return i;
    }

    // Returns the position after a quoted string, doubled quotes included.
    size_t stringEnd(size_t quote) const {
        size_t i = quote + 1;
        while (i < src.size()) {
            if (src[i] != '\'') { i++; continue; }
            if (at(i + 1) != '\'') return i + 1;
            i += 2;
        }
        return src.size();
    }

    // Returns the position after a literal array #( ... ) or byte array
    // #[ ... ], nested ones included.
    size_t literalArrayEnd(size_t open) const {
        int depth = 0;
        size_t i = open;
        while (i < src.size()) {
            char c = src[i];
            if (c == '\'') { i = stringEnd(i); continue; }
            if (c == '$') { i += 2; continue; }
            if (c == '(' || c == '[') depth++;
            if ((c == ')' || c == ']') && --depth == 0) return i + 1;
            i++;
        }
        return src.size();
    }

    size_t numberEnd(size_t from) const {
        size_t i = from;
        while (i < src.size()) {
            char c = src[i];
            bool fraction = c == '.' && std::isdigit(static_cast<unsigned char>(at(i + 1)));
            if (!isWordCharacter(c) && !fraction) break;
            i++;
        }
        return i;
    }

    Token symbol(size_t hash) {
        char c = at(hash + 1);
        if (c == '(' || c == '[') return make(TokenKind::Literal, hash, literalArrayEnd(hash + 1));
        if (c == '\'') return make(TokenKind::Literal, hash, stringEnd(hash + 1));
        size_t i = hash + 1;
        while (i < src.size() && (isWordCharacter(src[i]) || src[i] == ':')) i++;
        if (i == hash + 1) i = binaryEnd(i);
        return make(TokenKind::Literal, hash, i);
    }

    Token word(size_t start) {
        size_t end = wordEnd(start);
        if (at(end) == ':' && at(end + 1) != '=') return make(TokenKind::Keyword, start, end + 1);
        return make(TokenKind::Identifier, start, end);
    }

    Token next() {
        size_t start = pos;
        char c = src[pos];
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') return word(start);
        if (std::isdigit(static_cast<unsigned char>(c))) return make(TokenKind::Literal, start, numberEnd(start));
        if (c == '\'') return make(TokenKind::Literal, start, stringEnd(start));
        if (c == '$') return make(TokenKind::Literal, start, std::min(start + 2, src.size()));
        if (c == '#') return symbol(start);
        if (c == ':' && at(pos + 1) == '=') return make(TokenKind::Assign, start, start + 2);
        if (c == ':') return make(TokenKind::BlockArg, start, wordEnd(start + 1));
        if (std::string("()[].;^|{}").find(c) != std::string::npos) return make(TokenKind::Special, start, start + 1);
        if (isBinaryCharacter(c)) return make(TokenKind::Binary, start, binaryEnd(start));
        return make(TokenKind::Special, start, start + 1);
    }
};

class Parser {
public:
    explicit Parser(const std::string& source) : tokens(Tokenizer(source).tokens()) {}

    SyntaxTree parseMethod() {
        readPattern();
        readTemporariesAndPragmas();
        tree.statements = statements("");
        return std::move(tree);
    }

private:
    std::vector<Token> tokens;
    size_t pos{0};
    SyntaxTree tree;

    const Token& peek(size_t ahead = 0) const {
        static const Token end;
        return pos + ahead < tokens.size() ? tokens[pos + ahead] : end;
    }
    bool isSpecial(const char* text, size_t ahead = 0) const {
        return peek(ahead).kind == TokenKind::Special && peek(ahead).text == text;
    }
    bool isBinary(const char* text) const {
        return peek().kind == TokenKind::Binary && peek().text == text;
    }
    const Token& take() {
        const Token& token = peek();
        if (pos < tokens.size()) pos++;
        return token;
    }

    int add(SyntaxNode node) {
        tree.nodes.push_back(std::move(node));
        return static_cast<int>(tree.nodes.size() - 1);
    }

    // Reads the method's selector and argument names. A binary selector may be
    // "|", which the tokenizer reads as a separator.
    void readPattern() {
        if (peek().kind == TokenKind::Binary || isSpecial("|")) {
            tree.selector = take().text;
            if (peek().kind == TokenKind::Identifier) tree.argumentNames.push_back(take().text);
            return;
        }
        if (peek().kind == TokenKind::Identifier) {
            tree.selector = take().text;
            return;
        }
        while (peek().kind == TokenKind::Keyword) {
            tree.selector += take().text;
            if (peek().kind == TokenKind::Identifier) tree.argumentNames.push_back(take().text);
        }
    }

    // Returns the names up to the closing "|", which it takes.
    std::vector<std::string> namesUntilBar() {
        std::vector<std::string> names;
        while (peek().kind != TokenKind::End && !isSpecial("|")) {
            if (peek().kind == TokenKind::Identifier) names.push_back(peek().text);
            take();
        }
        take();
        return names;
    }

    void skipUntil(const char* closing, TokenKind kind) {
        while (peek().kind != TokenKind::End && !(peek().kind == kind && peek().text == closing)) take();
        take();
    }

    // Pragmas such as <primitive: 1> may sit before or after the temporaries.
    void readTemporariesAndPragmas() {
        bool temporaries = false;
        while (true) {
            if (isBinary("<")) { take(); skipUntil(">", TokenKind::Binary); continue; }
            if (!temporaries && isSpecial("|")) {
                temporaries = true;
                take();
                tree.temporaryNames = namesUntilBar();
                continue;
            }
            return;
        }
    }

    std::vector<int> statements(const char* closing) {
        std::vector<int> list;
        while (peek().kind != TokenKind::End && !isSpecial(closing)) {
            if (isSpecial(".") || isSpecial("^")) { take(); continue; }
            size_t before = pos;
            int node = expression();
            if (node >= 0) list.push_back(node);
            if (pos == before) take();
        }
        return list;
    }

    int expression() {
        if (peek().kind == TokenKind::Identifier && peek(1).kind == TokenKind::Assign) {
            const Token& name = take();
            take();
            int variable = add({SyntaxNode::Kind::Leaf, name.start, name.end});
            SyntaxNode assignment{SyntaxNode::Kind::Assignment, name.start, name.start};
            assignment.children.push_back(variable);
            assignment.receiver = expression();
            if (assignment.receiver >= 0) assignment.end = tree.at(assignment.receiver).end;
            return add(std::move(assignment));
        }
        int primaryNode = primary();
        if (primaryNode < 0) return -1;
        int first = keywordMessage(binaryMessages(unaryMessages(primaryNode)));
        if (!isSpecial(";")) return first;
        return cascade(first);
    }

    // The first message of a cascade has already been parsed; the others go to its receiver.
    int cascade(int first) {
        size_t start = tree.at(first).start;
        SyntaxNode node{SyntaxNode::Kind::Cascade, start, tree.at(first).end};
        node.receiver = tree.at(first).receiver;
        node.children.push_back(first);
        while (isSpecial(";")) {
            take();
            int receiverCopy = add({SyntaxNode::Kind::Leaf, start, start});
            int message = keywordMessage(binaryMessages(unaryMessages(receiverCopy)));
            node.children.push_back(message);
            node.end = tree.at(message).end;
        }
        return add(std::move(node));
    }

    int primary() {
        const Token& token = peek();
        if (token.kind == TokenKind::Identifier || token.kind == TokenKind::Literal) {
            take();
            return add({SyntaxNode::Kind::Leaf, token.start, token.end});
        }
        if (isSpecial("(")) return parenthesized();
        if (isSpecial("[")) return block();
        if (isSpecial("{")) return brace();
        if (isBinary("-")) { take(); return primary(); }
        return -1;
    }

    // A send in parentheses spans them, the way a client marks it. Any other
    // node keeps its own range.
    int parenthesized() {
        size_t start = take().start;
        int inner = expression();
        size_t end = take().end;
        if (inner < 0) return add({SyntaxNode::Kind::Leaf, start, end});
        SyntaxNode& node = tree.nodes[static_cast<size_t>(inner)];
        if (node.kind == SyntaxNode::Kind::Send || node.kind == SyntaxNode::Kind::Cascade) {
            node.start = start;
            node.end = end;
        }
        return inner;
    }

    int block() {
        size_t start = take().start;
        SyntaxNode node{SyntaxNode::Kind::Block, start, start};
        bool hasArguments = false;
        while (peek().kind == TokenKind::BlockArg) {
            std::string name = take().text.substr(1);
            if (!name.empty()) node.argumentNames.push_back(name);
            hasArguments = true;
        }
        if (hasArguments && isSpecial("|")) take();
        if (isSpecial("|")) {
            take();
            node.temporaryNames = namesUntilBar();
        }
        node.children = statements("]");
        node.end = take().end;
        return add(std::move(node));
    }

    int brace() {
        size_t start = take().start;
        SyntaxNode node{SyntaxNode::Kind::Brace, start, start};
        node.children = statements("}");
        node.end = take().end;
        return add(std::move(node));
    }

    int send(int receiver, std::string selector, std::vector<int> arguments, size_t end) {
        SyntaxNode node{SyntaxNode::Kind::Send, tree.at(receiver).start, end};
        node.selector = std::move(selector);
        node.receiver = receiver;
        node.arguments = std::move(arguments);
        return add(std::move(node));
    }

    int unaryMessages(int receiver) {
        while (peek().kind == TokenKind::Identifier && peek(1).kind != TokenKind::Assign) {
            const Token& name = take();
            receiver = send(receiver, name.text, {}, name.end);
        }
        return receiver;
    }

    int binaryMessages(int receiver) {
        while (peek().kind == TokenKind::Binary || isSpecial("|")) {
            std::string op = take().text;
            int argument = primary();
            if (argument < 0) break;
            argument = unaryMessages(argument);
            receiver = send(receiver, op, {argument}, tree.at(argument).end);
        }
        return receiver;
    }

    int keywordMessage(int receiver) {
        if (peek().kind != TokenKind::Keyword) return receiver;
        std::string selector;
        std::vector<int> arguments;
        while (peek().kind == TokenKind::Keyword) {
            selector += take().text;
            int argument = primary();
            if (argument < 0) break;
            arguments.push_back(binaryMessages(unaryMessages(argument)));
        }
        size_t end = arguments.empty() ? tree.at(receiver).end : tree.at(arguments.back()).end;
        return send(receiver, selector, std::move(arguments), end);
    }
};

} // namespace

bool SyntaxTree::sendsMessages(int index) const {
    if (index < 0) return false;
    const SyntaxNode& node = at(index);
    if (node.kind == SyntaxNode::Kind::Send || node.kind == SyntaxNode::Kind::Cascade) return true;
    if (node.kind == SyntaxNode::Kind::Assignment) return sendsMessages(node.receiver);
    for (int child : node.children) {
        if (sendsMessages(child)) return true;
    }
    return false;
}

SyntaxTree parseMethodSyntax(const std::string& source) {
    return Parser(source).parseMethod();
}

} // namespace smalltalk
