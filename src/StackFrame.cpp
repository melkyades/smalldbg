#include "smalldbg/StackFrame.h"
#include <iostream>
#include <iomanip>

namespace smalldbg {

// A caller's ip is where it resumes, which is never 0; a frame a VM copied off
// the stack has none.
std::vector<RegisterValue> StackFrame::registerValues() const {
    using Role = RegisterValue::Role;
    auto values = registers.arch->registerValues(registers);
    if (allRegisters) return values;
    for (auto& one : values) {
        bool recovered = one.role == Role::Sp || one.role == Role::Fp
                         || (one.role == Role::Ip && one.value != 0u);
        if (!recovered) one.value.reset();
    }
    return values;
}

void StackFrame::print(std::ostream& os, size_t frameNumber) const {
    os << "#" << frameNumber << "  ";
    os << "0x" << std::hex << std::setw(16) << std::setfill('0') 
       << ip() << std::dec << " in ";
    
    if (!functionName.empty()) {
        os << functionName;
        if (functionOffset > 0) {
            os << "+0x" << std::hex << functionOffset << std::dec;
        }
    } else {
        os << "??";
    }
    
    if (!moduleName.empty()) {
        os << " (" << moduleName << ")";
    }
    os << "\n";
    
    if (!sourceFile.empty() && sourceLine > 0) {
        os << "    at " << sourceFile << ":" << sourceLine << "\n";
    }
    
    if (!localVariables.empty()) {
        os << "    Local variables:\n";
        for (const auto& var : localVariables) {
            var.print(os);
            os << "\n";
        }
    }
}

} // namespace smalldbg
