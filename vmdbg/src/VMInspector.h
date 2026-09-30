#pragma once

#include <string>
#include <cstdint>

namespace vmdbg {

/// VM-level introspection behind the /regions, /classify and /inspect routes.
///
/// Dialects implement this so the server never handles VM-specific types.
class VMInspector {
public:
    virtual ~VMInspector() = default;

    /// The VM's evaluator stack, when it has one.
    struct StackRegion {
        bool valid{false};
        uint64_t base{0};
        uint64_t sp{0};
        uint64_t bp{0};
    };
    virtual StackRegion evaluatorStack() const = 0;
};

} // namespace vmdbg
