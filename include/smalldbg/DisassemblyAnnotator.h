// SmallDBG: disassembly annotation
#pragma once

#include "Types.h"
#include "Disassembler.h"
#include "symbols/SymbolProvider.h"
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace smalldbg {

class Debugger;
class SymbolProvider;

/** Returns the address an instruction names as a value, such as a constant
 *  loaded into a register, or nothing when it names none. A number below
 *  kSmallestPlausibleAddress is taken for a constant rather than an address.
 **/
std::optional<Address> immediateAddressOf(const DisasmInsn& instruction);

/** Returns the address of memory an instruction reads or writes, or nothing
 *  when that address is in a register rather than in the encoding. **/
std::optional<Address> memoryOperandOf(const DisasmInsn& instruction);

// Below this an operand is a constant rather than an address.
inline constexpr Address kSmallestPlausibleAddress = 0x10000;

/** An AnnotatedInstruction is an instruction with what could be said about
 *  it. **/
struct AnnotatedInstruction {
    Address address{0};
    int size{0};
    std::string bytes;
    std::string text;
    std::string comment;   // what the instruction refers to
    std::string label;     // a label that belongs before this instruction
};

/** An AnnotationSource names the addresses a listing refers to. Finding the
 *  addresses is the same for every VM; naming them is not, since a VM keeps
 *  the names of its code and data in its own heap. **/
class AnnotationSource {
public:
    virtual ~AnnotationSource() = default;

    /** Returns the name of the code at `address`, or an empty name. **/
    virtual std::string codeLabel(Address address) const = 0;

    /** Returns where the code containing `address` starts, so that a branch
     *  into it reads as "name+0x1c", or 0 when that is not known. **/
    virtual Address codeStart(Address /*address*/) const { return 0; }

    /** Returns the name of the data at `address`, or an empty name. A VM
     *  names code and data from different places. **/
    virtual std::string dataLabel(Address /*address*/) const { return {}; }

    /** Returns a label to place at `address` whether or not anything
     *  branches there, such as a method entry, or an empty name. **/
    virtual std::string labelAt(Address /*address*/) const { return {}; }

    /** Returns false when the listing should not label the places its jumps
     *  land, as for a source that places its own labels. **/
    virtual bool wantsBranchLabels() const { return true; }

    /** Returns a note on what the encoding alone cannot say, such as an
     *  inline cache's selector, or an empty note. **/
    virtual std::string noteFor(const DisasmInsn& /*instruction*/) const {
        return {};
    }
};

/** A SymbolAnnotationSource names code and data by native symbol. It keeps
 *  the last symbol found, since consecutive instructions fall in the same
 *  routine, and does not look up addresses outside every module. **/
class SymbolAnnotationSource : public AnnotationSource {
public:
    explicit SymbolAnnotationSource(Debugger& debugger);
    ~SymbolAnnotationSource() override;

    std::string codeLabel(Address address) const override;
    Address codeStart(Address address) const override;
    std::string dataLabel(Address address) const override;
    /** Returns the symbol that starts at `address`, qualified by its module,
     *  or an empty name when none starts there. **/
    std::string labelAt(Address address) const override;

private:
    struct Cache;
    std::optional<Symbol> lookup(Address address) const;

    Debugger& debugger;
    std::unique_ptr<Cache> cache;
};

/** A DisassemblyAnnotator names what each instruction of a listing refers to:
 *  where a branch goes, and the code or data an operand names. It labels the
 *  places in the listing that its jumps land on. **/
class DisassemblyAnnotator {
public:
    DisassemblyAnnotator(Debugger& debugger, const AnnotationSource& source);

    std::vector<AnnotatedInstruction> annotate(
        const std::vector<DisasmInsn>& instructions) const;

private:
    AnnotatedInstruction annotateOne(
        const DisasmInsn& instruction, Address first, Address last,
        std::map<Address, std::string>& labels) const;
    bool nameNumber(AnnotatedInstruction& annotated, Address address,
                    const std::string& name) const;
    std::string describeSlot(AnnotatedInstruction& annotated, Address slot) const;
    std::string describe(Address target, bool indirect) const;
    std::string nameOf(Address address) const;
    std::optional<Address> pointerAt(Address address) const;

    Debugger& debugger;
    const AnnotationSource& source;
};

} // namespace smalldbg
