#pragma once

#include <string>
#include <cstdint>

namespace webside {

/// VM-level introspection behind the /regions, /classify and /inspect routes.
///
/// Dialects implement this so the server never handles VM-specific types:
/// object rendering is returned already formatted as JSON.
class WebsideInspector {
public:
    virtual ~WebsideInspector() = default;

    /// The VM's evaluator stack, when it has one.
    struct StackRegion {
        bool valid{false};
        uint64_t base{0};
        uint64_t sp{0};
        uint64_t bp{0};
    };
    virtual StackRegion evaluatorStack() const = 0;

    /// JSON description of the object at `oop`, with at most `maxSlots` slots.
    virtual std::string inspectObject(uint64_t oop, int maxSlots) const = 0;
};

} // namespace webside
