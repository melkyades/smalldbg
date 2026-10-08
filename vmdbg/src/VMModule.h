#pragma once

#include <string>

namespace vmdbg {

/** A VMModule describes the module that holds a VM's runtime. A dump or a
 *  trace of the VM cannot be read without that module's symbol file, unless
 *  the runtime exports what is read from it. **/
struct VMModule {
    std::string name;             // empty when the VM has no such module
    bool needsSymbolFile{true};   // false when its exports are enough
    std::string note;             // what the symbols are for, logged when missing
};

} // namespace vmdbg
