// DwarfTypes.cpp — Minimal DWARF5 parser for extracting C/C++ type info
// from Mach-O .o files on macOS (referenced via N_OSO stab entries).

#include "DwarfTypes.h"
#include "SymbolsInternal.h"

#ifdef __APPLE__
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <cxxabi.h>
#include <algorithm>
#endif

namespace smalldbg {

// =========================================================================
// DWARF constants (only what we use)
// =========================================================================

enum : uint16_t {
    DW5_TAG_array_type        = 0x01,
    DW5_TAG_class_type        = 0x02,
    DW5_TAG_enumeration_type  = 0x04,
    DW5_TAG_formal_parameter  = 0x05,
    DW5_TAG_lexical_block     = 0x0b,
    DW5_TAG_member            = 0x0d,
    DW5_TAG_pointer_type      = 0x0f,
    DW5_TAG_reference_type    = 0x10,
    DW5_TAG_compile_unit      = 0x11,
    DW5_TAG_structure_type    = 0x13,
    DW5_TAG_typedef           = 0x16,
    DW5_TAG_union_type        = 0x17,
    DW5_TAG_subrange_type     = 0x21,
    DW5_TAG_base_type         = 0x24,
    DW5_TAG_const_type        = 0x26,
    DW5_TAG_subprogram        = 0x2E,
    DW5_TAG_variable          = 0x34,
    DW5_TAG_volatile_type     = 0x35,
    DW5_TAG_namespace         = 0x39,
    DW5_TAG_rvalue_ref_type   = 0x42,
    DW5_TAG_restrict_type     = 0x37,
    DW5_TAG_inlined_subroutine = 0x1D,
};

enum : uint16_t {
    DW5_AT_location           = 0x02,
    DW5_AT_name               = 0x03,
    DW5_AT_byte_size          = 0x0b,
    DW5_AT_low_pc             = 0x11,
    DW5_AT_high_pc            = 0x12,
    DW5_AT_count              = 0x37,
    DW5_AT_data_member_loc    = 0x38,
    DW5_AT_declaration        = 0x3c,
    DW5_AT_encoding           = 0x3e,
    DW5_AT_external           = 0x3f,
    DW5_AT_abstract_origin     = 0x31,
    DW5_AT_frame_base         = 0x40,
    DW5_AT_specification      = 0x47,
    DW5_AT_type               = 0x49,
    DW5_AT_linkage_name       = 0x6e,
    DW5_AT_str_offsets_base   = 0x72,
    DW5_AT_calling_convention = 0x36,
    DW5_AT_accessibility      = 0x32,
};

enum : uint8_t {
    DW5_FORM_addr          = 0x01,
    DW5_FORM_data2         = 0x05,
    DW5_FORM_data4         = 0x06,
    DW5_FORM_data1         = 0x0b,
    DW5_FORM_sdata         = 0x0d,
    DW5_FORM_udata         = 0x0f,
    DW5_FORM_ref4          = 0x13,
    DW5_FORM_sec_offset    = 0x17,
    DW5_FORM_exprloc       = 0x18,
    DW5_FORM_flag_present  = 0x19,
    DW5_FORM_addrx         = 0x1b,
    DW5_FORM_implicit_const = 0x21,
    DW5_FORM_rnglistx      = 0x23,
    DW5_FORM_strx1         = 0x25,
    DW5_FORM_strx2         = 0x26,
    DW5_FORM_strx4         = 0x28,
    DW5_FORM_data8         = 0x08,
    DW5_FORM_ref_addr      = 0x10,
    DW5_FORM_block1        = 0x0a,
    DW5_FORM_loclistx      = 0x22,
    DW5_FORM_ref1          = 0x11,
    DW5_FORM_ref2          = 0x12,
    DW5_FORM_strp          = 0x0e,
    DW5_FORM_flag          = 0x0c,
    DW5_FORM_string        = 0x08, // actually same value as data8, need to check
};

enum : uint8_t {
    DW5_ATE_boolean      = 0x02,
    DW5_ATE_float        = 0x04,
    DW5_ATE_signed       = 0x05,
    DW5_ATE_signed_char  = 0x06,
    DW5_ATE_unsigned     = 0x07,
    DW5_ATE_unsigned_char = 0x08,
    DW5_ATE_UTF          = 0x10,
};

// =========================================================================
// LEB128 helpers
// =========================================================================

static uint64_t readULEB128(const uint8_t*& p, const uint8_t* end) {
    uint64_t result = 0;
    unsigned shift = 0;
    while (p < end) {
        uint8_t byte = *p++;
        result |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

static int64_t readSLEB128(const uint8_t*& p, const uint8_t* end) {
    int64_t result = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    while (p < end) {
        byte = *p++;
        result |= static_cast<int64_t>(byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) break;
    }
    if (shift < 64 && (byte & 0x40))
        result |= -(static_cast<int64_t>(1) << shift);
    return result;
}

// =========================================================================
// Abbreviation table
// =========================================================================

struct AbbrevAttr {
    uint16_t name;
    uint8_t form;
    int64_t implicitConst{0}; // for DW_FORM_implicit_const
};

struct AbbrevEntry {
    uint16_t tag;
    bool hasChildren;
    std::vector<AbbrevAttr> attrs;
};

using AbbrevTable = std::unordered_map<uint32_t, AbbrevEntry>;

static AbbrevTable parseAbbrevTable(const uint8_t* data, size_t size,
                                     uint32_t offset) {
    AbbrevTable table;
    const uint8_t* p = data + offset;
    const uint8_t* end = data + size;

    while (p < end) {
        uint32_t code = static_cast<uint32_t>(readULEB128(p, end));
        if (code == 0) break;

        AbbrevEntry entry;
        entry.tag = static_cast<uint16_t>(readULEB128(p, end));
        entry.hasChildren = (*p++ != 0);

        while (p < end) {
            uint16_t attrName = static_cast<uint16_t>(readULEB128(p, end));
            uint8_t form = static_cast<uint8_t>(readULEB128(p, end));
            if (attrName == 0 && form == 0) break;

            AbbrevAttr attr;
            attr.name = attrName;
            attr.form = form;
            if (form == DW5_FORM_implicit_const)
                attr.implicitConst = readSLEB128(p, end);
            entry.attrs.push_back(attr);
        }

        table[code] = std::move(entry);
    }

    return table;
}

// =========================================================================
// DWARF form value reading
// =========================================================================

struct AttrValue {
    uint64_t unsigned_val{0};
    int64_t signed_val{0};
    std::string string_val;
    std::vector<uint8_t> block_val;   // location expression bytes (exprloc/block)
    bool is_present{false};
};

// Skip or read one attribute value. Returns the value if it's a form we
// care about, otherwise just advances the pointer.
static AttrValue readFormValue(uint8_t form, const uint8_t*& p,
                                const uint8_t* end, uint8_t addrSize,
                                // string resolution
                                const uint8_t* strSection, size_t strSize,
                                const uint8_t* strOffsSection, size_t strOffsSize,
                                uint32_t strOffsBase) {
    AttrValue val;
    val.is_present = true;

    switch (form) {
    case DW5_FORM_addr:
        if (p + addrSize <= end) {
            if (addrSize == 8) { std::memcpy(&val.unsigned_val, p, 8); }
            else if (addrSize == 4) { uint32_t v; std::memcpy(&v, p, 4); val.unsigned_val = v; }
            p += addrSize;
        }
        break;
    case DW5_FORM_data1:
        if (p < end) val.unsigned_val = *p++;
        break;
    case DW5_FORM_data2:
        if (p + 2 <= end) { uint16_t v; std::memcpy(&v, p, 2); val.unsigned_val = v; p += 2; }
        break;
    case DW5_FORM_data4:
        if (p + 4 <= end) { uint32_t v; std::memcpy(&v, p, 4); val.unsigned_val = v; p += 4; }
        break;
    case DW5_FORM_data8:
        if (p + 8 <= end) { std::memcpy(&val.unsigned_val, p, 8); p += 8; }
        break;
    case DW5_FORM_sdata:
        val.signed_val = readSLEB128(p, end);
        val.unsigned_val = static_cast<uint64_t>(val.signed_val);
        break;
    case DW5_FORM_udata:
        val.unsigned_val = readULEB128(p, end);
        break;
    case DW5_FORM_ref4:
        if (p + 4 <= end) { uint32_t v; std::memcpy(&v, p, 4); val.unsigned_val = v; p += 4; }
        break;
    case DW5_FORM_ref1:
        if (p < end) val.unsigned_val = *p++;
        break;
    case DW5_FORM_ref2:
        if (p + 2 <= end) { uint16_t v; std::memcpy(&v, p, 2); val.unsigned_val = v; p += 2; }
        break;
    case DW5_FORM_ref_addr:
        // DWARF32: 4 bytes
        if (p + 4 <= end) { uint32_t v; std::memcpy(&v, p, 4); val.unsigned_val = v; p += 4; }
        break;
    case DW5_FORM_sec_offset:
        if (p + 4 <= end) { uint32_t v; std::memcpy(&v, p, 4); val.unsigned_val = v; p += 4; }
        break;
    case DW5_FORM_strx1:
    case DW5_FORM_strx2:
    case DW5_FORM_strx4: {
        uint32_t index = 0;
        if (form == DW5_FORM_strx1 && p < end) { index = *p++; }
        else if (form == DW5_FORM_strx2 && p + 2 <= end) { uint16_t v; std::memcpy(&v, p, 2); index = v; p += 2; }
        else if (form == DW5_FORM_strx4 && p + 4 <= end) { std::memcpy(&index, p, 4); p += 4; }

        // Resolve: strOffsBase + index * 4 → offset into .debug_str
        uint32_t tableOffset = strOffsBase + index * 4;
        if (strOffsSection && tableOffset + 4 <= strOffsSize) {
            uint32_t strOffset;
            std::memcpy(&strOffset, strOffsSection + tableOffset, 4);
            if (strSection && strOffset < strSize) {
                val.string_val = reinterpret_cast<const char*>(strSection + strOffset);
            }
        }
        break;
    }
    case DW5_FORM_strp:
        if (p + 4 <= end) {
            uint32_t strOffset; std::memcpy(&strOffset, p, 4); p += 4;
            if (strSection && strOffset < strSize)
                val.string_val = reinterpret_cast<const char*>(strSection + strOffset);
        }
        break;
    case DW5_FORM_exprloc: {
        uint64_t len = readULEB128(p, end);
        if (p + len <= end) {
            val.block_val.assign(p, p + len);
            p += len;
        }
        break;
    }
    case DW5_FORM_block1:
        if (p < end) {
            uint8_t len = *p++;
            if (p + len <= end) {
                val.block_val.assign(p, p + len);
                p += len;
            }
        }
        break;
    case DW5_FORM_flag_present:
        val.unsigned_val = 1;
        break;
    case DW5_FORM_flag:
        if (p < end) val.unsigned_val = *p++;
        break;
    case DW5_FORM_rnglistx:
    case DW5_FORM_addrx:
    case DW5_FORM_loclistx:
        val.unsigned_val = readULEB128(p, end);
        break;
    case DW5_FORM_implicit_const:
        // value is in the abbreviation table, passed separately
        break;
    default:
        // Unknown form — can't continue safely
        p = end;
        break;
    }
    return val;
}

// =========================================================================
// Parsed DIE — temporary storage during DWARF walk
// =========================================================================

struct ParsedDIE {
    uint32_t offset{0};
    uint16_t tag{0};
    uint32_t parentOffset{0};
    std::string name;
    std::string linkageName;
    uint64_t byteSize{0};
    uint32_t typeRef{0};
    uint64_t memberLocation{0};
    uint8_t encoding{0};
    bool hasTypeRef{false};
    bool hasByteSize{false};
    bool hasMemberLocation{false};
    bool isDeclaration{false};
    // Subprogram address range
    uint64_t lowPC{0};
    uint64_t highPC{0};
    bool hasLowPC{false};
    bool hasHighPC{false};
    bool highPCIsLength{false};
    // DW_AT_specification / DW_AT_abstract_origin reference
    uint32_t specRef{0};
    bool hasSpecRef{false};
    // Location expressions (for frame_base, variable locations)
    std::vector<uint8_t> frameBaseExpr;
    std::vector<uint8_t> locationExpr;
};

// =========================================================================
// Type resolution — convert parsed DIEs into NativeTypeInfo
// =========================================================================

static NativeTypeKind kindFromEncoding(uint8_t encoding) {
    switch (encoding) {
    case DW5_ATE_boolean:      return NativeTypeKind::Bool;
    case DW5_ATE_signed:       return NativeTypeKind::Int;
    case DW5_ATE_signed_char:  return NativeTypeKind::Char;
    case DW5_ATE_unsigned:     return NativeTypeKind::UInt;
    case DW5_ATE_unsigned_char: return NativeTypeKind::Char;
    case DW5_ATE_float:        return NativeTypeKind::Float;
    case DW5_ATE_UTF:          return NativeTypeKind::Char;
    default:                   return NativeTypeKind::Unknown;
    }
}

static NativeTypeKind kindFromTag(uint16_t tag) {
    switch (tag) {
    case DW5_TAG_structure_type:   return NativeTypeKind::Struct;
    case DW5_TAG_class_type:       return NativeTypeKind::Class;
    case DW5_TAG_union_type:       return NativeTypeKind::Union;
    case DW5_TAG_enumeration_type: return NativeTypeKind::Enum;
    case DW5_TAG_pointer_type:     return NativeTypeKind::Pointer;
    case DW5_TAG_reference_type:   return NativeTypeKind::Reference;
    case DW5_TAG_rvalue_ref_type:  return NativeTypeKind::Reference;
    case DW5_TAG_typedef:          return NativeTypeKind::Typedef;
    case DW5_TAG_const_type:       return NativeTypeKind::Const;
    case DW5_TAG_volatile_type:    return NativeTypeKind::Volatile;
    case DW5_TAG_array_type:       return NativeTypeKind::Array;
    default:                       return NativeTypeKind::Unknown;
    }
}

// Build the qualified name from a DIE by walking parent namespace/class DIEs.
static std::string buildQualifiedName(
    uint32_t dieOffset,
    const std::unordered_map<uint32_t, ParsedDIE>& dies) {

    auto it = dies.find(dieOffset);
    if (it == dies.end() || it->second.name.empty()) return "";

    std::string result = it->second.name;
    uint32_t parent = it->second.parentOffset;

    while (parent != 0) {
        auto pit = dies.find(parent);
        if (pit == dies.end()) break;
        auto& pdie = pit->second;
        if (pdie.tag == DW5_TAG_namespace ||
            pdie.tag == DW5_TAG_structure_type ||
            pdie.tag == DW5_TAG_class_type) {
            if (!pdie.name.empty())
                result = pdie.name + "::" + result;
        }
        parent = pdie.parentOffset;
    }
    return simplifyTypeName(std::move(result));
}

// Resolve a type reference to its display name.
static std::string resolveTypeName(
    uint32_t typeRef, uint32_t cuOffset,
    const std::unordered_map<uint32_t, ParsedDIE>& dies) {

    uint32_t absRef = cuOffset + typeRef;
    auto it = dies.find(absRef);
    if (it == dies.end()) return "?";

    auto& die = it->second;
    switch (die.tag) {
    case DW5_TAG_pointer_type:
        if (die.hasTypeRef)
            return resolveTypeName(die.typeRef, cuOffset, dies) + " *";
        return "void *";
    case DW5_TAG_reference_type:
    case DW5_TAG_rvalue_ref_type:
        if (die.hasTypeRef)
            return resolveTypeName(die.typeRef, cuOffset, dies) + " &";
        return "void &";
    case DW5_TAG_const_type:
        if (die.hasTypeRef)
            return "const " + resolveTypeName(die.typeRef, cuOffset, dies);
        return "const void";
    case DW5_TAG_volatile_type:
        if (die.hasTypeRef)
            return "volatile " + resolveTypeName(die.typeRef, cuOffset, dies);
        return "volatile void";
    case DW5_TAG_typedef:
        return buildQualifiedName(absRef, dies);
    case DW5_TAG_restrict_type:
        if (die.hasTypeRef)
            return resolveTypeName(die.typeRef, cuOffset, dies);
        return "void";
    case DW5_TAG_array_type:
        if (die.hasTypeRef)
            return resolveTypeName(die.typeRef, cuOffset, dies) + "[]";
        return "?[]";
    default:
        return buildQualifiedName(absRef, dies);
    }
}

static NativeTypeKind resolveTypeKind(
    uint32_t typeRef, uint32_t cuOffset,
    const std::unordered_map<uint32_t, ParsedDIE>& dies) {

    uint32_t absRef = cuOffset + typeRef;
    auto it = dies.find(absRef);
    if (it == dies.end()) return NativeTypeKind::Unknown;
    auto& die = it->second;

    if (die.tag == DW5_TAG_base_type)
        return kindFromEncoding(die.encoding);
    return kindFromTag(die.tag);
}

// Resolve the ultimate target of a pointer/reference/typedef/const/volatile chain.
static std::string resolveTargetStructName(
    uint32_t typeRef, uint32_t cuOffset,
    const std::unordered_map<uint32_t, ParsedDIE>& dies) {

    uint32_t absRef = cuOffset + typeRef;
    auto it = dies.find(absRef);
    if (it == dies.end()) return "";

    auto& die = it->second;
    switch (die.tag) {
    case DW5_TAG_pointer_type:
    case DW5_TAG_reference_type:
    case DW5_TAG_rvalue_ref_type:
    case DW5_TAG_const_type:
    case DW5_TAG_volatile_type:
    case DW5_TAG_typedef:
    case DW5_TAG_restrict_type:
        if (die.hasTypeRef)
            return resolveTargetStructName(die.typeRef, cuOffset, dies);
        return "";
    case DW5_TAG_structure_type:
    case DW5_TAG_class_type:
    case DW5_TAG_union_type:
        return buildQualifiedName(absRef, dies);
    default:
        return "";
    }
}

// =========================================================================
// DWARF location expression evaluator (simple cases only)
// =========================================================================

static uint32_t extractFrameBaseReg(const std::vector<uint8_t>& expr) {
    if (expr.empty()) return 29; // default to FP on ARM64
    uint8_t op = expr[0];
    // DW_OP_reg0..DW_OP_reg31
    if (op >= 0x50 && op <= 0x6f)
        return op - 0x50;
    // DW_OP_regx
    if (op == 0x90 && expr.size() >= 2) {
        const uint8_t* p = expr.data() + 1;
        const uint8_t* end = expr.data() + expr.size();
        return static_cast<uint32_t>(readULEB128(p, end));
    }
    return 29;
}

static DwarfVariable evaluateVariableLocation(
    const std::vector<uint8_t>& expr, uint32_t frameBaseReg,
    const std::string& name, const std::string& typeName,
    uint64_t typeSize, bool isParam) {

    DwarfVariable var;
    var.name = name;
    var.typeName = typeName;
    var.typeSize = typeSize;
    var.isParameter = isParam;

    if (expr.empty()) return var;

    const uint8_t* p = expr.data();
    const uint8_t* end = p + expr.size();
    uint8_t op = *p++;

    // DW_OP_reg0..DW_OP_reg31: value is in register N
    if (op >= 0x50 && op <= 0x6f) {
        var.locationType = VariableLocation::Register;
        var.dwarfRegNum = op - 0x50;
        return var;
    }

    // DW_OP_regx: value is in register (ULEB128)
    if (op == 0x90) {
        var.locationType = VariableLocation::Register;
        var.dwarfRegNum = static_cast<uint32_t>(readULEB128(p, end));
        return var;
    }

    // DW_OP_fbreg + SLEB128: relative to frame base
    if (op == 0x91) {
        int64_t offset = readSLEB128(p, end);
        var.locationType = VariableLocation::FrameRelative;
        var.locationOffset = offset;
        return var;
    }

    // DW_OP_breg0..DW_OP_breg31 + SLEB128: register + offset
    if (op >= 0x70 && op <= 0x8f) {
        uint32_t reg = op - 0x70;
        int64_t offset = readSLEB128(p, end);
        if (reg == frameBaseReg) {
            var.locationType = VariableLocation::FrameRelative;
            var.locationOffset = offset;
        } else if (reg == 31) { // SP on ARM64, RSP on x64
            var.locationType = VariableLocation::StackRelative;
            var.locationOffset = offset;
        } else {
            // Other register-based addressing — treat as register for now
            var.locationType = VariableLocation::Register;
            var.dwarfRegNum = reg;
        }
        return var;
    }

    // DW_OP_addr: absolute address
    if (op == 0x03 && p + 8 <= end) {
        uint64_t addr;
        std::memcpy(&addr, p, 8);
        var.locationType = VariableLocation::Memory;
        var.locationOffset = static_cast<int64_t>(addr);
        return var;
    }

    return var; // Unknown expression
}

// =========================================================================
// Process subprograms from parsed DIEs
// =========================================================================

static void processSubprogramDIE(
    const ParsedDIE& spDie, uint32_t spOffset, uint32_t cuOffset,
    const std::unordered_map<uint32_t, ParsedDIE>& dies,
    std::vector<DwarfSubprogram>& out) {

    if (!spDie.hasLowPC || !spDie.hasHighPC) return;
    if (spDie.isDeclaration) return;

    DwarfSubprogram sub;
    sub.lowPC = spDie.lowPC;
    sub.highPC = spDie.highPCIsLength ? (spDie.lowPC + spDie.highPC) : spDie.highPC;

    // Resolve name: check this DIE first, then follow specification chain
    std::string linkName = spDie.linkageName;
    std::string shortName = spDie.name;
    uint32_t nameOffset = spOffset;
    if (linkName.empty() && shortName.empty() && spDie.hasSpecRef) {
        uint32_t absRef = cuOffset + spDie.specRef;
        auto sit = dies.find(absRef);
        if (sit != dies.end()) {
            linkName = sit->second.linkageName;
            shortName = sit->second.name;
            nameOffset = absRef;
        }
    }

    if (!linkName.empty())
        sub.name = demangle(linkName.c_str());
    else if (!shortName.empty())
        sub.name = buildQualifiedName(nameOffset, dies);

    if (sub.name.empty()) return;

    uint32_t frameBaseReg = extractFrameBaseReg(spDie.frameBaseExpr);

    // Collect direct children and children of lexical blocks
    for (auto& [offset, die] : dies) {
        bool isChild = (die.parentOffset == spOffset);
        if (!isChild) {
            // Check if inside a lexical block that's a child of this subprogram
            auto pit = dies.find(die.parentOffset);
            if (pit != dies.end() && pit->second.tag == DW5_TAG_lexical_block &&
                pit->second.parentOffset == spOffset) {
                isChild = true;
            }
        }
        if (!isChild) continue;

        bool isParam = (die.tag == DW5_TAG_formal_parameter);
        bool isLocal = (die.tag == DW5_TAG_variable);
        if (!isParam && !isLocal) continue;
        if (die.name.empty()) continue;
        if (die.locationExpr.empty()) continue;

        std::string typeName;
        uint64_t typeSize = 0;
        if (die.hasTypeRef) {
            typeName = resolveTypeName(die.typeRef, cuOffset, dies);
            uint32_t absRef = cuOffset + die.typeRef;
            auto tit = dies.find(absRef);
            if (tit != dies.end() && tit->second.hasByteSize)
                typeSize = tit->second.byteSize;
        }

        auto var = evaluateVariableLocation(
            die.locationExpr, frameBaseReg,
            die.name, typeName, typeSize, isParam);
        sub.variables.push_back(std::move(var));
    }

    out.push_back(std::move(sub));
}

// =========================================================================
// Process one compilation unit's DIEs and merge into the database.
// =========================================================================

static void processCompilationUnit(
    const std::unordered_map<uint32_t, ParsedDIE>& dies,
    uint32_t cuOffset,
    std::unordered_map<std::string, NativeTypeInfo>& typeDB,
    std::unordered_map<std::string, std::string>& varDB) {

    // Collect struct/class members by parent offset
    std::unordered_map<uint32_t, std::vector<uint32_t>> childMembers;
    for (auto& [offset, die] : dies) {
        if (die.tag == DW5_TAG_member && !die.isDeclaration)
            childMembers[die.parentOffset].push_back(offset);
    }

    auto processStructDIE = [&](const ParsedDIE& die, uint32_t offset) {
        if (die.isDeclaration) return; // forward declaration
        if (die.name.empty()) return;

        std::string qualName = buildQualifiedName(offset, dies);
        if (qualName.empty()) return;

        // Skip if we already have a definition with fields
        auto existing = typeDB.find(qualName);
        if (existing != typeDB.end() && !existing->second.fields.empty())
            return;

        NativeTypeInfo info;
        info.name = qualName;
        info.kind = kindFromTag(die.tag);
        info.size = die.byteSize;

        auto mit = childMembers.find(offset);
        if (mit != childMembers.end()) {
            // Sort members by offset for consistent ordering
            auto& memberOffsets = mit->second;
            std::sort(memberOffsets.begin(), memberOffsets.end(),
                [&](uint32_t a, uint32_t b) {
                    return dies.at(a).memberLocation < dies.at(b).memberLocation;
                });

            for (uint32_t moff : memberOffsets) {
                auto& mdie = dies.at(moff);
                NativeField field;
                field.name = mdie.name;
                field.offset = mdie.memberLocation;
                if (mdie.hasTypeRef) {
                    field.typeName = resolveTypeName(mdie.typeRef, cuOffset, dies);
                    field.typeKind = resolveTypeKind(mdie.typeRef, cuOffset, dies);
                    // Estimate field size from type
                    uint32_t absRef = cuOffset + mdie.typeRef;
                    auto tit = dies.find(absRef);
                    if (tit != dies.end() && tit->second.hasByteSize)
                        field.size = tit->second.byteSize;
                }
                info.fields.push_back(std::move(field));
            }

            // Fill in field sizes from gaps if not set
            for (size_t i = 0; i < info.fields.size(); i++) {
                if (info.fields[i].size == 0) {
                    if (i + 1 < info.fields.size())
                        info.fields[i].size = info.fields[i + 1].offset - info.fields[i].offset;
                    else if (info.size > info.fields[i].offset)
                        info.fields[i].size = info.size - info.fields[i].offset;
                }
            }
        }

        typeDB[qualName] = std::move(info);
    };

    // Process all struct/class/union definitions
    for (auto& [offset, die] : dies) {
        if (die.tag == DW5_TAG_structure_type ||
            die.tag == DW5_TAG_class_type ||
            die.tag == DW5_TAG_union_type) {
            processStructDIE(die, offset);
        }
    }

    // Process pointer/typedef types → target type name
    for (auto& [offset, die] : dies) {
        if (die.tag == DW5_TAG_pointer_type ||
            die.tag == DW5_TAG_typedef) {
            if (!die.hasTypeRef) continue;
            // Use the full type name (e.g. "Egg::Runtime *" not just "Egg::Runtime")
            uint32_t cuRelOffset = offset - cuOffset;
            std::string name = resolveTypeName(cuRelOffset, cuOffset, dies);
            if (name.empty()) continue;
            std::string targetName = resolveTargetStructName(die.typeRef, cuOffset, dies);
            if (!targetName.empty()) {
                NativeTypeInfo info;
                info.name = name;
                info.kind = kindFromTag(die.tag);
                info.size = (die.tag == DW5_TAG_pointer_type) ? 8 : 0;
                info.targetTypeName = targetName;
                typeDB.emplace(name, std::move(info));
            }
        }
    }

    // Process base types
    for (auto& [offset, die] : dies) {
        if (die.tag == DW5_TAG_base_type && !die.name.empty()) {
            std::string name = die.name;
            if (typeDB.find(name) == typeDB.end()) {
                NativeTypeInfo info;
                info.name = name;
                info.kind = kindFromEncoding(die.encoding);
                info.size = die.byteSize;
                typeDB[name] = std::move(info);
            }
        }
    }

    // Process global variables with linkage names
    for (auto& [offset, die] : dies) {
        if (die.tag != DW5_TAG_variable) continue;
        if (!die.hasTypeRef) continue;
        if (die.linkageName.empty() && die.name.empty()) continue;

        std::string typeName = resolveTypeName(die.typeRef, cuOffset, dies);
        if (typeName.empty()) continue;

        // Use the demangled linkage name or the qualified name
        std::string varName;
        if (!die.linkageName.empty()) {
            varName = demangle(die.linkageName.c_str());
        } else {
            varName = buildQualifiedName(offset, dies);
        }
        if (!varName.empty())
            varDB[varName] = typeName;
    }
}

// =========================================================================
// DWARF section parser — walk one CU in .debug_info
// =========================================================================

#ifdef __APPLE__

struct DwarfSections {
    const uint8_t* info{nullptr};
    size_t infoSize{0};
    const uint8_t* abbrev{nullptr};
    size_t abbrevSize{0};
    const uint8_t* str{nullptr};
    size_t strSize{0};
    const uint8_t* strOffsets{nullptr};
    size_t strOffsetsSize{0};
};

static void parseDwarfCU(const DwarfSections& sec,
                          std::unordered_map<std::string, NativeTypeInfo>& typeDB,
                          std::unordered_map<std::string, std::string>& varDB,
                          std::vector<DwarfSubprogram>& subprograms) {

    const uint8_t* p = sec.info;
    const uint8_t* infoEnd = sec.info + sec.infoSize;

    while (p < infoEnd) {
        // CU header
        const uint8_t* cuStart = p;
        uint32_t cuLength;
        std::memcpy(&cuLength, p, 4); p += 4;
        if (cuLength == 0 || cuLength == 0xffffffff) break;

        const uint8_t* cuEnd = p + cuLength;
        if (cuEnd > infoEnd) break;

        uint16_t version; std::memcpy(&version, p, 2); p += 2;
        if (version < 2 || version > 5) { p = cuEnd; continue; }

        uint8_t unitType = 0;
        uint8_t addrSize;
        uint32_t abbrevOffset;

        if (version >= 5) {
            unitType = *p++;
            addrSize = *p++;
            std::memcpy(&abbrevOffset, p, 4); p += 4;
        } else {
            std::memcpy(&abbrevOffset, p, 4); p += 4;
            addrSize = *p++;
        }

        uint32_t cuOffset = static_cast<uint32_t>(cuStart - sec.info);

        // Parse abbreviation table for this CU
        auto abbrevTable = parseAbbrevTable(sec.abbrev, sec.abbrevSize, abbrevOffset);

        // State for tree walking
        std::unordered_map<uint32_t, ParsedDIE> dies;
        std::vector<uint32_t> parentStack;
        parentStack.push_back(0); // root
        uint32_t strOffsBase = 0;

        // First pass: parse all DIEs
        while (p < cuEnd) {
            uint32_t dieOffset = static_cast<uint32_t>(p - sec.info);
            uint32_t abbrevCode = static_cast<uint32_t>(readULEB128(p, cuEnd));

            if (abbrevCode == 0) {
                // NULL entry — pop parent
                if (!parentStack.empty()) parentStack.pop_back();
                continue;
            }

            auto ait = abbrevTable.find(abbrevCode);
            if (ait == abbrevTable.end()) break; // can't continue

            auto& abbrev = ait->second;
            ParsedDIE die;
            die.offset = dieOffset;
            die.tag = abbrev.tag;
            die.parentOffset = parentStack.empty() ? 0 : parentStack.back();

            // Read attribute values
            for (auto& attr : abbrev.attrs) {
                AttrValue val;
                if (attr.form == DW5_FORM_implicit_const) {
                    val.unsigned_val = static_cast<uint64_t>(attr.implicitConst);
                    val.signed_val = attr.implicitConst;
                    val.is_present = true;
                } else {
                    val = readFormValue(attr.form, p, cuEnd, addrSize,
                                        sec.str, sec.strSize,
                                        sec.strOffsets, sec.strOffsetsSize,
                                        strOffsBase);
                }

                switch (attr.name) {
                case DW5_AT_name:
                    die.name = val.string_val;
                    break;
                case DW5_AT_linkage_name:
                    die.linkageName = val.string_val;
                    break;
                case DW5_AT_byte_size:
                    die.byteSize = val.unsigned_val;
                    die.hasByteSize = true;
                    break;
                case DW5_AT_type:
                    die.typeRef = static_cast<uint32_t>(val.unsigned_val);
                    die.hasTypeRef = true;
                    break;
                case DW5_AT_data_member_loc:
                    die.memberLocation = val.unsigned_val;
                    die.hasMemberLocation = true;
                    break;
                case DW5_AT_encoding:
                    die.encoding = static_cast<uint8_t>(val.unsigned_val);
                    break;
                case DW5_AT_declaration:
                    die.isDeclaration = (val.unsigned_val != 0);
                    break;
                case DW5_AT_str_offsets_base:
                    strOffsBase = static_cast<uint32_t>(val.unsigned_val);
                    break;
                case DW5_AT_low_pc:
                    die.lowPC = val.unsigned_val;
                    die.hasLowPC = true;
                    break;
                case DW5_AT_high_pc:
                    die.highPC = val.unsigned_val;
                    die.hasHighPC = true;
                    die.highPCIsLength = (attr.form != DW5_FORM_addr &&
                                         attr.form != DW5_FORM_addrx);
                    break;
                case DW5_AT_frame_base:
                    die.frameBaseExpr = std::move(val.block_val);
                    break;
                case DW5_AT_location:
                    die.locationExpr = std::move(val.block_val);
                    break;
                case DW5_AT_specification:
                case DW5_AT_abstract_origin:
                    die.specRef = static_cast<uint32_t>(val.unsigned_val);
                    die.hasSpecRef = true;
                    break;
                }
            }

            dies[dieOffset] = std::move(die);

            if (abbrev.hasChildren)
                parentStack.push_back(dieOffset);
        }

        // Second pass: resolve types and merge into database
        processCompilationUnit(dies, cuOffset, typeDB, varDB);

        // Third pass: extract subprogram variables
        for (auto& [offset, die] : dies) {
            if (die.tag == DW5_TAG_subprogram)
                processSubprogramDIE(die, offset, cuOffset, dies, subprograms);
        }

        p = cuEnd;
    }
}

// =========================================================================
// Locate DWARF sections in a Mach-O .o file
// =========================================================================

static DwarfSections findDwarfSections(const uint8_t* base, size_t fileSize) {
    DwarfSections sec;

    auto* header = reinterpret_cast<const mach_header_64*>(base);
    if (header->magic != MH_MAGIC_64) return sec;

    const uint8_t* cmd = base + sizeof(mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        auto* lc = reinterpret_cast<const load_command*>(cmd);
        if (cmd + sizeof(load_command) > base + fileSize) break;

        if (lc->cmd == LC_SEGMENT_64) {
            auto* seg = reinterpret_cast<const segment_command_64*>(cmd);
            // In .o files (MH_OBJECT) the segment name is empty but
            // each section carries its own segname. Check per-section.
            auto* sections = reinterpret_cast<const section_64*>(
                cmd + sizeof(segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                auto& sect = sections[s];
                if (std::strncmp(sect.segname, "__DWARF", 7) != 0) continue;
                if (sect.offset + sect.size > fileSize) continue;
                const uint8_t* data = base + sect.offset;
                size_t sz = sect.size;

                if (std::strncmp(sect.sectname, "__debug_info", 12) == 0 &&
                    (sect.sectname[12] == '\0' || sect.sectname[12] == ' ')) {
                    sec.info = data; sec.infoSize = sz;
                } else if (std::strncmp(sect.sectname, "__debug_abbrev", 14) == 0) {
                    sec.abbrev = data; sec.abbrevSize = sz;
                } else if (std::strncmp(sect.sectname, "__debug_str", 11) == 0 &&
                           (sect.sectname[11] == '\0' || sect.sectname[11] == ' ')) {
                    sec.str = data; sec.strSize = sz;
                } else if (std::strncmp(sect.sectname, "__debug_str_offs", 16) == 0) {
                    sec.strOffsets = data; sec.strOffsetsSize = sz;
                }
            }
        }
        cmd += lc->cmdsize;
    }
    return sec;
}

// =========================================================================
// N_OSO stab entry collector — finds .o file paths from a Mach-O binary
// =========================================================================

static std::vector<std::string> collectNOSOEntries(const std::string& path) {
    std::vector<std::string> entries;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return entries;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return entries; }
    size_t fileSize = static_cast<size_t>(st.st_size);
    if (fileSize < sizeof(mach_header_64)) { close(fd); return entries; }

    void* mapped = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return entries;

    auto* base = static_cast<const uint8_t*>(mapped);
    uint32_t magic = *reinterpret_cast<const uint32_t*>(base);

    const uint8_t* machBase = base;
    size_t machSize = fileSize;

    // Handle fat binary
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        auto* fatHeader = reinterpret_cast<const fat_header*>(base);
        uint32_t nArch = OSSwapBigToHostInt32(fatHeader->nfat_arch);
        auto* arches = reinterpret_cast<const fat_arch*>(base + sizeof(fat_header));
        bool found = false;
        for (uint32_t i = 0; i < nArch; i++) {
            cpu_type_t cpuType = OSSwapBigToHostInt32(arches[i].cputype);
#if defined(__arm64__) || defined(__aarch64__)
            if (cpuType == CPU_TYPE_ARM64) {
#else
            if (cpuType == CPU_TYPE_X86_64) {
#endif
                uint32_t offset = OSSwapBigToHostInt32(arches[i].offset);
                uint32_t size = OSSwapBigToHostInt32(arches[i].size);
                if (offset + size <= fileSize) {
                    machBase = base + offset;
                    machSize = size;
                    found = true;
                }
                break;
            }
        }
        if (!found) { munmap(mapped, fileSize); return entries; }
    }

    auto* header = reinterpret_cast<const mach_header_64*>(machBase);
    if (header->magic != MH_MAGIC_64) { munmap(mapped, fileSize); return entries; }

    // Find symtab
    const uint8_t* cmd = machBase + sizeof(mach_header_64);
    const struct symtab_command* symtab = nullptr;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        auto* lc = reinterpret_cast<const load_command*>(cmd);
        if (lc->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<const struct symtab_command*>(cmd);
            break;
        }
        cmd += lc->cmdsize;
    }

    if (!symtab || symtab->nsyms == 0) { munmap(mapped, fileSize); return entries; }

    auto* nlists = reinterpret_cast<const nlist_64*>(machBase + symtab->symoff);
    auto* strtab = reinterpret_cast<const char*>(machBase + symtab->stroff);

    // N_OSO stab entries have n_type == 0x66
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const nlist_64& nl = nlists[i];
        if ((nl.n_type & 0xff) == 0x66) { // N_OSO
            uint32_t strIdx = nl.n_un.n_strx;
            if (strIdx < symtab->strsize) {
                const char* name = strtab + strIdx;
                if (name[0] != '\0')
                    entries.emplace_back(name);
            }
        }
    }

    munmap(mapped, fileSize);
    return entries;
}

// =========================================================================
// Archive (.a) member extraction
// =========================================================================

static bool extractArchiveMember(const std::string& archivePath,
                                  const std::string& memberName,
                                  std::function<void(const uint8_t*, size_t)> callback) {
    int fd = open(archivePath.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    size_t fileSize = static_cast<size_t>(st.st_size);

    void* mapped = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return false;

    auto* base = static_cast<const uint8_t*>(mapped);

    // Check magic
    if (fileSize < 8 || std::memcmp(base, "!<arch>\n", 8) != 0) {
        munmap(mapped, fileSize);
        return false;
    }

    size_t pos = 8;
    // Read the extended name table if present
    std::string extNames;
    bool found = false;

    while (pos + 60 <= fileSize) {
        // ar header: name[16] date[12] uid[6] gid[6] mode[8] size[10] fmag[2]
        const char* hdr = reinterpret_cast<const char*>(base + pos);
        if (hdr[58] != '`' || hdr[59] != '\n') break;

        // Parse size
        char sizeBuf[11] = {};
        std::memcpy(sizeBuf, hdr + 48, 10);
        size_t memberSize = static_cast<size_t>(std::atoll(sizeBuf));

        // Parse name
        char nameBuf[17] = {};
        std::memcpy(nameBuf, hdr, 16);
        std::string entryName(nameBuf);
        // Trim trailing spaces
        while (!entryName.empty() && entryName.back() == ' ')
            entryName.pop_back();

        size_t dataStart = pos + 60;
        if (dataStart + memberSize > fileSize) break;

        // Handle BSD extended names (#1/N format)
        std::string actualName = entryName;
        size_t nameInData = 0;
        if (entryName.substr(0, 3) == "#1/") {
            nameInData = static_cast<size_t>(std::atoi(entryName.c_str() + 3));
            if (nameInData > 0 && nameInData <= memberSize) {
                actualName = std::string(
                    reinterpret_cast<const char*>(base + dataStart), nameInData);
                // Remove trailing nulls
                while (!actualName.empty() && actualName.back() == '\0')
                    actualName.pop_back();
            }
        }

        // Check for extended name section
        if (entryName == "//" || entryName == "ARFILENAMES/") {
            extNames = std::string(reinterpret_cast<const char*>(base + dataStart),
                                   memberSize);
        }

        if (actualName == memberName) {
            callback(base + dataStart + nameInData,
                     memberSize - nameInData);
            found = true;
            break;
        }

        // Advance to next entry (aligned to 2 bytes)
        pos = dataStart + memberSize;
        if (pos & 1) pos++;
    }

    munmap(mapped, fileSize);
    return found;
}

#endif // __APPLE__

// =========================================================================
// DwarfTypeDatabase public implementation
// =========================================================================

void DwarfTypeDatabase::parseDwarfFromObject(const uint8_t* base, size_t size) {
#ifdef __APPLE__
    auto sections = findDwarfSections(base, size);
    if (!sections.info || !sections.abbrev) return;
    parseDwarfCU(sections, types, variableTypes, subprograms);
#else
    (void)base; (void)size;
#endif
}

void DwarfTypeDatabase::parseObjectFile(const std::string& path) {
#ifdef __APPLE__
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return; }
    size_t fileSize = static_cast<size_t>(st.st_size);

    void* mapped = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return;

    parseDwarfFromObject(static_cast<const uint8_t*>(mapped), fileSize);
    munmap(mapped, fileSize);
#else
    (void)path;
#endif
}

void DwarfTypeDatabase::parseArchiveMember(const std::string& archivePath,
                                            const std::string& memberName) {
#ifdef __APPLE__
    extractArchiveMember(archivePath, memberName,
        [this](const uint8_t* data, size_t size) {
            parseDwarfFromObject(data, size);
        });
#else
    (void)archivePath; (void)memberName;
#endif
}

void DwarfTypeDatabase::loadFromBinary(const std::string& binaryPath) {
    if (loaded) return;
    loaded = true;

#ifdef __APPLE__
    auto entries = collectNOSOEntries(binaryPath);
    for (auto& entry : entries) {
        // Check for archive member notation: "path/to/lib.a(member.o)"
        auto parenPos = entry.find('(');
        if (parenPos != std::string::npos && entry.back() == ')') {
            std::string archPath = entry.substr(0, parenPos);
            std::string member = entry.substr(parenPos + 1,
                                               entry.size() - parenPos - 2);
            parseArchiveMember(archPath, member);
        } else {
            parseObjectFile(entry);
        }
    }

#else
    (void)binaryPath;
#endif
}

const NativeTypeInfo* DwarfTypeDatabase::findType(const std::string& name) const {
    auto it = types.find(name);
    return (it != types.end()) ? &it->second : nullptr;
}

std::optional<std::string> DwarfTypeDatabase::getVariableTypeName(
    const std::string& name) const {
    auto it = variableTypes.find(name);
    return (it != variableTypes.end()) ? std::optional(it->second) : std::nullopt;
}

const DwarfSubprogram* DwarfTypeDatabase::findSubprogram(uint64_t pc) const {
    for (auto& sub : subprograms) {
        if (pc >= sub.lowPC && pc < sub.highPC)
            return &sub;
    }
    return nullptr;
}

const DwarfSubprogram* DwarfTypeDatabase::findSubprogramByName(
    const std::string& name) const {

    for (auto& sub : subprograms) {
        if (sub.name == name) return &sub;
    }
    return nullptr;
}

} // namespace smalldbg
