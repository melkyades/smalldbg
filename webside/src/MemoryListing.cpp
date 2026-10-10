#include "MemoryListing.h"
#include "WebsideSession.h"

#include <smalldbg/Debugger.h>
#include <smalldbg/symbols/SymbolProvider.h>

#include <algorithm>
#include <cstdio>

namespace webside {

using vmdbg::MemType;
using vmdbg::MemTypeRange;

MemoryListing::MemoryListing(const WebsideSession& s,
                             const std::map<uint64_t, std::string>& labels)
    : session(s), userLabels(labels), source(s.annotationSource()) {}

MemoryListing::~MemoryListing() = default;

// Code is annotated in one pass, so that a jump in one run labels where it
// lands in another.
Json MemoryListing::rows(uint64_t address, const std::vector<uint8_t>& bytes) {
    base = address;
    memory = &bytes;
    out = Json::array();
    labelled.clear();
    code.clear();

    const auto runs = session.memoryTypes().classify(address, address + bytes.size());
    for (const auto& run : runs) {
        if (run.type != MemType::Code) continue;
        auto part = decode(run);
        code.insert(code.end(), part.begin(), part.end());
    }
    smalldbg::DisassemblyAnnotator annotator(session.debugger(), *source);
    annotated = annotator.annotate(code);

    size_t next = 0;
    for (const auto& run : runs) {
        switch (run.type) {
        case MemType::Code:        next = addCode(run, next); break;
        case MemType::Struct:      addLayout(run); break;
        case MemType::StringAscii:
        case MemType::StringUtf16:
        case MemType::StringUtf32: addStrings(run); break;
        default:                   addData(run); break;
        }
    }
    return out;
}

// A run can start in the middle of an instruction, so where decoding fails it
// skips a byte and starts again; an instruction cut short at the end of what
// was read is left as bytes.
std::vector<smalldbg::DisasmInsn> MemoryListing::decode(const MemTypeRange& run) const {
    std::vector<smalldbg::DisasmInsn> decoded;
    auto* disassembler = session.debugger().getDisassembler();
    uint64_t at = run.start;
    while (at < run.end) {
        size_t offset = static_cast<size_t>(at - base);
        if (offset >= memory->size()) break;
        size_t size = std::min(static_cast<size_t>(run.end - at),
                               memory->size() - offset);
        auto part = disassembler->disassemble(memory->data() + offset, size, at);
        if (part.empty()) {
            if (memory->size() - offset < 16) break;
            at++;
            continue;
        }
        decoded.insert(decoded.end(), part.begin(), part.end());
        at = std::max(at + 1, part.back().address + part.back().size);
    }
    return decoded;
}

// Bytes in a code run that do not decode still take their place, or the
// listing would lose address space.
size_t MemoryListing::addCode(const MemTypeRange& run, size_t next) {
    uint64_t at = run.start;
    for (; next < code.size() && code[next].address < run.end; next++) {
        if (code[next].address < run.start) continue;
        if (code[next].address > at)
            addData({at, code[next].address, MemType::Data1});
        addInstruction(next);
        at = code[next].address + code[next].size;
    }
    if (at < run.end) addData({at, run.end, MemType::Data1});
    return next;
}

// Adds an instruction's row. Following it leads to where a direct branch goes,
// or for any other instruction to the memory its operand names.
void MemoryListing::addInstruction(size_t index) {
    const auto& instruction = annotated[index];
    addLabel(instruction.address, instruction.label);
    auto row = Json::object()
        .set("address", address(instruction.address))
        .set("size", instruction.size)
        .set("bytes", instruction.bytes)
        .set("text", instruction.text);
    if (!instruction.comment.empty()) row.set("comment", instruction.comment);

    const auto& decoded = code[index];
    if (decoded.target && !decoded.targetIsSlot)
        row.set("target", address(*decoded.target));
    else if (auto operand = smalldbg::memoryOperandOf(decoded))
        row.set("target", address(*operand));
    out.add(std::move(row));
}

// Adds one row per element, each at a multiple of its size; the bytes before
// the first and after the last are rows of their own.
void MemoryListing::addData(const MemTypeRange& run) {
    size_t size = vmdbg::memTypeElementSize(run.type);
    if (size == 0) size = 1;
    uint64_t at = run.start;
    const uint64_t aligned = std::min(run.end, (at + size - 1) / size * size);
    if (size > 1 && aligned > at) {
        addData({at, aligned, MemType::Data1});
        at = aligned;
    }
    const char* mnemonic = size == 1 ? "db" : size == 2 ? "dw"
                         : size == 4 ? "dd" : "dq";
    for (; at + size <= run.end; at += size) {
        addLabel(at, source->labelAt(at));
        uint64_t value = valueAt(at, size);
        char text[32];
        std::snprintf(text, sizeof text, "0x%0*llx", static_cast<int>(size * 2),
                      static_cast<unsigned long long>(value));
        auto row = Json::object()
            .set("type", "data")
            .set("address", address(at))
            .set("size", static_cast<int>(size))
            .set("bytes", bytesAt(at, size))
            .set("text", std::string(mnemonic) + " " + text)
            .set("value", std::string(text));
        std::string note = dataNote(at, size, value);
        if (!note.empty()) row.set("comment", note);
        out.add(std::move(row));
    }
    if (at < run.end) addData({at, run.end, MemType::Data1});
}

// Returns a word's name: its field inside a native struct, or for any other
// pointer-sized word what it points at. Returns an empty text for neither.
std::string MemoryListing::dataNote(uint64_t at, size_t size, uint64_t value) const {
    auto field = session.debugger().getSymbolProvider()->getFieldAt(at);
    if (field && !field->name.empty())
        return field->typeName.empty() ? field->name
                                       : field->name + " : " + field->typeName;
    if (size != session.pointerSize() || value == 0) return {};
    return source->dataLabel(value);
}

// A string runs to its terminator or to the end of its run, whichever comes
// first; what is not text shows as a dot. Zeros between strings, such as the
// padding after one, are one row.
void MemoryListing::addStrings(const MemTypeRange& run) {
    const size_t unit = vmdbg::memTypeElementSize(run.type);
    const char* encoding = vmdbg::memTypeName(run.type);
    uint64_t at = run.start;
    while (at + unit <= run.end) {
        addLabel(at, source->labelAt(at));
        uint64_t zeros = at;
        while (zeros + unit <= run.end && valueAt(zeros, unit) == 0) zeros += unit;
        if (zeros - at > unit) {
            out.add(Json::object()
                .set("type", "data")
                .set("address", address(at))
                .set("size", static_cast<int>(zeros - at))
                .set("bytes", bytesAt(at, std::min<uint64_t>(zeros - at, 8)))
                .set("text", "db " + std::to_string(zeros - at) + " dup (0)"));
            at = zeros;
            continue;
        }
        std::string text;
        uint64_t next = at;
        bool terminated = false;
        while (next + unit <= run.end && text.size() < 512) {
            uint64_t character = valueAt(next, unit);
            next += unit;
            if (character == 0) { terminated = true; break; }
            text += character >= 0x20 && character < 0x7F
                ? static_cast<char>(character) : '.';
        }
        out.add(Json::object()
            .set("type", "string")
            .set("address", address(at))
            .set("size", static_cast<int>(next - at))
            .set("encoding", encoding)
            .set("bytes", bytesAt(at, std::min<uint64_t>(next - at, 8)))
            .set("text", "d" + std::string(1, encoding[0]) + " \"" + text + "\""
                         + (terminated ? ",0" : ""))
            .set("value", text));
        at = next;
    }
}

// A layout the VM defined is read by the session, which knows what its fields
// mean; one it cannot read shows as bytes.
void MemoryListing::addLayout(const MemTypeRange& run) {
    const size_t offset = static_cast<size_t>(run.start - base);
    const size_t size = std::min<size_t>(static_cast<size_t>(run.end - run.start),
                                         memory->size() - offset);
    std::vector<uint8_t> bytes(memory->begin() + offset,
                               memory->begin() + offset + size);
    std::string text = session.layoutText(run, bytes);
    if (text.empty()) {
        addData({run.start, run.end, MemType::Data1});
        return;
    }
    addLabel(run.start, source->labelAt(run.start));
    out.add(Json::object()
        .set("type", "data")
        .set("address", address(run.start))
        .set("size", static_cast<int>(size))
        .set("bytes", bytesAt(run.start, size))
        .set("text", text));
}

// Adds at most one label per address, the user's name before any other.
void MemoryListing::addLabel(uint64_t at, const std::string& label) {
    auto user = userLabels.find(at);
    const bool byUser = user != userLabels.end();
    const std::string& text = byUser ? user->second : label;
    if (text.empty() || !labelled.insert(at).second) return;
    auto row = Json::object()
        .set("type", "label")
        .set("address", address(at))
        .set("text", text);
    if (byUser) row.set("user", true);
    out.add(std::move(row));
}

uint64_t MemoryListing::valueAt(uint64_t at, size_t size) const {
    uint64_t value = 0;
    for (size_t k = 0; k < size; k++) {
        size_t offset = static_cast<size_t>(at - base) + k;
        if (offset >= memory->size()) break;
        value |= static_cast<uint64_t>((*memory)[offset]) << (8 * k);
    }
    return value;
}

std::string MemoryListing::bytesAt(uint64_t at, size_t size) const {
    static const char* digits = "0123456789abcdef";
    std::string hex;
    for (size_t k = 0; k < size; k++) {
        size_t offset = static_cast<size_t>(at - base) + k;
        if (offset >= memory->size()) break;
        hex += digits[(*memory)[offset] >> 4];
        hex += digits[(*memory)[offset] & 0xF];
    }
    return hex;
}

Json MemoryListing::address(uint64_t at) const {
    return session.addressHex(at);
}

} // namespace webside
