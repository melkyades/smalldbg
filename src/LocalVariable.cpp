#include "smalldbg/Types.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Thread.h"
#include "smalldbg/Debugger.h"
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace smalldbg {

// CV register constants for x64
constexpr uint32_t CV_AMD64_RAX = 328;
constexpr uint32_t CV_AMD64_RCX = 329;
constexpr uint32_t CV_AMD64_RDX = 330;
constexpr uint32_t CV_AMD64_RBX = 331;
constexpr uint32_t CV_AMD64_RSP = 332;
constexpr uint32_t CV_AMD64_RBP = 333;
constexpr uint32_t CV_AMD64_RSI = 334;
constexpr uint32_t CV_AMD64_RDI = 335;
constexpr uint32_t CV_AMD64_R8 = 336;
constexpr uint32_t CV_AMD64_R9 = 337;
constexpr uint32_t CV_AMD64_R10 = 338;
constexpr uint32_t CV_AMD64_R11 = 339;
constexpr uint32_t CV_AMD64_R12 = 340;
constexpr uint32_t CV_AMD64_R13 = 341;
constexpr uint32_t CV_AMD64_R14 = 342;
constexpr uint32_t CV_AMD64_R15 = 343;

// x86 register constants (for 32-bit compatibility)
constexpr uint32_t CV_REG_EAX = 17;
constexpr uint32_t CV_REG_ECX = 18;
constexpr uint32_t CV_REG_EDX = 19;
constexpr uint32_t CV_REG_EBX = 20;

static std::optional<uint64_t> getRegisterValue(const Registers& regs, uint32_t regNum) {
    switch (regNum) {
        // x64 registers
        case CV_AMD64_RAX: return regs.x64.rax;
        case CV_AMD64_RCX: return regs.x64.rcx;
        case CV_AMD64_RDX: return regs.x64.rdx;
        case CV_AMD64_RBX: return regs.x64.rbx;
        case CV_AMD64_RSP: return regs.x64.rsp;
        case CV_AMD64_RBP: return regs.x64.rbp;
        case CV_AMD64_RSI: return regs.x64.rsi;
        case CV_AMD64_RDI: return regs.x64.rdi;
        case CV_AMD64_R8: return regs.x64.r8;
        case CV_AMD64_R9: return regs.x64.r9;
        case CV_AMD64_R10: return regs.x64.r10;
        case CV_AMD64_R11: return regs.x64.r11;
        case CV_AMD64_R12: return regs.x64.r12;
        case CV_AMD64_R13: return regs.x64.r13;
        case CV_AMD64_R14: return regs.x64.r14;
        case CV_AMD64_R15: return regs.x64.r15;
        
        // x86 registers (map to lower 32-bits of x64 regs)
        case CV_REG_EAX: return regs.x64.rax & 0xFFFFFFFF;
        case CV_REG_ECX: return regs.x64.rcx & 0xFFFFFFFF;
        case CV_REG_EDX: return regs.x64.rdx & 0xFFFFFFFF;
        case CV_REG_EBX: return regs.x64.rbx & 0xFFFFFFFF;
        
        default: return std::nullopt;
    }
}

std::optional<uint64_t> LocalVariable::getValue() const {
    if (!frame->hasRegisters) {
        return std::nullopt;
    }
    
    const Registers& regs = frame->registers;
    Address effectiveAddress = 0;
    
    switch (locationType) {
        case VariableLocation::Register:
            return getRegisterValue(regs, static_cast<uint32_t>(offset));
            
        case VariableLocation::FrameRelative:
            effectiveAddress = regs.x64.rbp + offset;
            break;
            
        case VariableLocation::StackRelative:
            effectiveAddress = regs.x64.rsp + offset;
            break;
            
        case VariableLocation::Memory:
            effectiveAddress = address;
            break;
            
        case VariableLocation::Unknown:
        default:
            return std::nullopt;
    }
    
    // Read value from memory
    Debugger* debugger = frame->thread->getDebugger();
    uint64_t value = 0;
    size_t readSize = std::min(size, sizeof(uint64_t));
    if (debugger->readMemory(effectiveAddress, &value, readSize) == Status::Ok) {
        return value;
    }
    
    return std::nullopt;
}

static std::string getRegisterName(uint32_t regNum) {
    switch (regNum) {
        // x64 registers
        case CV_AMD64_RAX: return "rax";
        case CV_AMD64_RCX: return "rcx";
        case CV_AMD64_RDX: return "rdx";
        case CV_AMD64_RBX: return "rbx";
        case CV_AMD64_RSP: return "rsp";
        case CV_AMD64_RBP: return "rbp";
        case CV_AMD64_RSI: return "rsi";
        case CV_AMD64_RDI: return "rdi";
        case CV_AMD64_R8: return "r8";
        case CV_AMD64_R9: return "r9";
        case CV_AMD64_R10: return "r10";
        case CV_AMD64_R11: return "r11";
        case CV_AMD64_R12: return "r12";
        case CV_AMD64_R13: return "r13";
        case CV_AMD64_R14: return "r14";
        case CV_AMD64_R15: return "r15";
        
        // x86 registers
        case CV_REG_EAX: return "eax";
        case CV_REG_ECX: return "ecx";
        case CV_REG_EDX: return "edx";
        case CV_REG_EBX: return "ebx";
        
        default: 
            return "reg" + std::to_string(regNum);
    }
}

std::string LocalVariable::getLocationString() const {
    std::ostringstream oss;
    
    switch (locationType) {
        case VariableLocation::Register:
            oss << getRegisterName(static_cast<uint32_t>(offset));
            break;
        case VariableLocation::FrameRelative:
            oss << "rbp" << (offset >= 0 ? "+" : "") << offset;
            break;
        case VariableLocation::StackRelative:
            oss << "rsp" << (offset >= 0 ? "+" : "") << offset;
            break;
        case VariableLocation::Memory:
            oss << "0x" << std::hex << address;
            break;
        case VariableLocation::Unknown:
        default:
            oss << "not yet allocated";
            break;
    }
    
    return oss.str();
}

void LocalVariable::print(std::ostream& os) const {
    os << "  " << name;
    if (!typeName.empty()) {
        os << " : " << typeName;
    }
    os << " (size=" << size << ", " << getLocationString() << ")";
    
    auto value = getValue();
    if (value) {
        os << " = 0x" << std::hex << *value << std::dec;
        if (size <= 8) {
            os << " (" << *value << ")";
        }
    }
}

} // namespace smalldbg
