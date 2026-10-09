#include "smalldbg/DisassemblyAnnotator.h"
#include "smalldbg/Arch.h"
#include "smalldbg/Debugger.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include <sstream>

namespace smalldbg {

namespace {

std::string hexString(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::optional<Address> plausible(const std::optional<uint64_t>& value) {
    if (!value || *value < kSmallestPlausibleAddress) return {};
    return *value;
}

} // namespace

std::optional<Address> immediateAddressOf(const DisasmInsn& instruction) {
    return plausible(instruction.immediate);
}

std::optional<Address> memoryOperandOf(const DisasmInsn& instruction) {
    return plausible(instruction.memory);
}

// ---------------------------------------------------------------------------
// SymbolAnnotationSource
// ---------------------------------------------------------------------------

struct SymbolAnnotationSource::Cache {
    std::vector<ModuleInfo> modules;
    bool modulesLoaded{false};
    mutable std::optional<Symbol> window;
};

SymbolAnnotationSource::SymbolAnnotationSource(Debugger& dbg)
    : debugger(dbg), cache(std::make_unique<Cache>()) {}

SymbolAnnotationSource::~SymbolAnnotationSource() = default;

// One lookup is behind every answer, so that they cannot disagree about what
// was found.
std::optional<Symbol> SymbolAnnotationSource::lookup(Address address) const {
    if (cache->window && address >= cache->window->address &&
        address - cache->window->address < cache->window->size)
        return cache->window;

    auto* symbols = debugger.getSymbolProvider();

    if (!cache->modulesLoaded) {
        cache->modules = symbols->getModules();
        cache->modulesLoaded = true;
    }
    // An address outside every module is in the heap; the symbol engine has
    // nothing to say about it and asking is the slow way to find that out.
    bool mapped = false;
    for (const auto& module : cache->modules) {
        if (address >= module.loadAddress && address < module.endAddress) {
            mapped = true;
            break;
        }
    }
    if (!mapped) return {};

    // The extent says whether the symbol also covers the addresses that
    // follow.
    auto symbol = symbols->getSymbolWithExtent(address);
    // A symbol without a name would read as a bare "+0x15f".
    if (!symbol || symbol->name.empty()) return {};
    if (symbol->size > 0) cache->window = symbol;
    return symbol;
}

std::string SymbolAnnotationSource::codeLabel(Address address) const {
    auto symbol = lookup(address);
    if (!symbol) return {};
    if (address == symbol->address) return symbol->name;
    return symbol->name + "+" + hexString(address - symbol->address);
}

Address SymbolAnnotationSource::codeStart(Address address) const {
    auto symbol = lookup(address);
    return symbol ? symbol->address : 0;
}

std::string SymbolAnnotationSource::dataLabel(Address address) const {
    return codeLabel(address);
}

// ---------------------------------------------------------------------------
// DisassemblyAnnotator
// ---------------------------------------------------------------------------

DisassemblyAnnotator::DisassemblyAnnotator(Debugger& dbg,
                                           const AnnotationSource& src)
    : debugger(dbg), source(src) {}

// Returns the pointer stored at `address`, read at the target's width, or
// nothing when it cannot be read or is null.
std::optional<Address> DisassemblyAnnotator::pointerAt(Address address) const {
    uint64_t value = 0;
    if (debugger.readMemory(address, &value, debugger.arch()->pointerSize())
        != Status::Ok || value == 0)
        return {};
    return value;
}

std::string DisassemblyAnnotator::nameOf(Address address) const {
    std::string label = source.codeLabel(address);
    if (!label.empty()) return label;
    // Known code reached in the middle still deserves a name.
    Address start = source.codeStart(address);
    if (start != 0 && start != address) {
        std::string owner = source.codeLabel(start);
        if (!owner.empty()) return owner + "+" + hexString(address - start);
    }
    return {};
}

std::string DisassemblyAnnotator::describe(Address target,
                                           bool indirect) const {
    if (!indirect) return nameOf(target);

    // The operand holds the destination, which is read from it; the operand
    // itself is named when it cannot be read.
    auto through = pointerAt(target);
    if (!through) return nameOf(target);
    std::string name = nameOf(*through);
    return name.empty() ? hexString(*through) : name;
}

// The name replaces the number in the text, along with the '#' some
// architectures write before one; the address moves into the comment, where
// the reader still needs it.
void DisassemblyAnnotator::nameBranch(AnnotatedInstruction& annotated,
                                      Address target,
                                      std::string& resolved) const {
    std::string number = hexString(target);
    auto at = annotated.text.find(number);
    if (at == std::string::npos) return;
    if (at > 0 && annotated.text[at - 1] == '#') {
        at--;
        number.insert(0, "#");
    }
    annotated.text.replace(at, number.size(), resolved);
    annotated.comment = hexString(target);
    resolved.clear();
}

AnnotatedInstruction DisassemblyAnnotator::annotateOne(
    const DisasmInsn& instruction, Address first, Address last,
    std::map<Address, std::string>& labels) const {
    AnnotatedInstruction annotated;
    annotated.address = instruction.address;
    annotated.size = instruction.size;
    annotated.bytes = instruction.bytes;
    annotated.text = instruction.text;
    annotated.comment = source.noteFor(instruction);

    std::string resolved;
    if (instruction.target) {
        Address target = *instruction.target;
        resolved = describe(target, instruction.targetIsSlot);
        if (!instruction.targetIsSlot && !resolved.empty())
            nameBranch(annotated, target, resolved);
        // A jump within the listing gets a label where it lands, so the
        // reader can see the loop rather than compare addresses.
        bool landsInView = target >= first && target < last;
        if (source.wantsBranchLabels() && instruction.isJump
            && !instruction.targetIsSlot && landsInView)
            labels.emplace(target, "L" + hexString(target));
    } else if (auto immediate = immediateAddressOf(instruction)) {
        resolved = source.dataLabel(*immediate);
    } else if (auto through = memoryOperandOf(instruction)) {
        // What matters is what is stored at the address; the address itself
        // is named when nothing is.
        if (auto value = pointerAt(*through))
            resolved = source.dataLabel(*value);
        if (resolved.empty()) resolved = source.dataLabel(*through);
    }

    if (!resolved.empty())
        annotated.comment = annotated.comment.empty()
            ? resolved : annotated.comment + " " + resolved;
    return annotated;
}

// The labels are placed once every branch is known. A label the source wants
// at an address wins over a generated one.
std::vector<AnnotatedInstruction> DisassemblyAnnotator::annotate(
    const std::vector<DisasmInsn>& instructions) const {
    std::vector<AnnotatedInstruction> out;
    if (instructions.empty()) return out;
    Address first = instructions.front().address;
    Address last = instructions.back().address + instructions.back().size;

    std::map<Address, std::string> labels;
    for (const auto& instruction : instructions)
        out.push_back(annotateOne(instruction, first, last, labels));

    for (auto& annotated : out) {
        std::string wanted = source.labelAt(annotated.address);
        if (!wanted.empty()) {
            annotated.label = wanted;
            continue;
        }
        auto it = labels.find(annotated.address);
        if (it != labels.end()) annotated.label = it->second;
    }
    return out;
}

} // namespace smalldbg
