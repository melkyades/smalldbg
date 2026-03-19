// Linux source-location resolution stub.
// DWARF line-table walking is not yet implemented.
#include "../../SourceResolver.h"

namespace smalldbg {

std::optional<SourceLocation> resolveSourceLocation(
    const std::string& binaryPath, uint64_t loadAddress, Address addr) {
    (void)binaryPath;
    (void)loadAddress;
    (void)addr;
    return std::nullopt;
}

} // namespace smalldbg
