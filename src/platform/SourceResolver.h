// Platform-specific source location resolution.
//
// On macOS the implementation uses `atos`; on Linux it returns nullopt
// (DWARF line-table walking is not yet implemented).
#pragma once

#include "../../include/smalldbg/SymbolProvider.h"
#include <optional>
#include <string>

namespace smalldbg {

std::optional<SourceLocation> resolveSourceLocation(
    const std::string& binaryPath, uint64_t loadAddress, Address addr);

} // namespace smalldbg
