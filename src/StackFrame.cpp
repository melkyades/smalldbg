#include "smalldbg/StackTrace.h"
#include <iostream>
#include <iomanip>

namespace smalldbg {

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
