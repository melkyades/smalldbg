#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace smalltalk { class Inspector; }

namespace vmdbg {

/** A named address range in the target: an object space, a code zone, a
 *  stack. Every VM divides its memory up somehow, and these are what answer
 *  "what is this address". **/
struct Region {
    std::string name;
    uint64_t start{0};
    uint64_t end{0};      // exclusive
    bool isObjectMemory{false};
    bool isCode{false};

    bool contains(uint64_t address) const {
        return address >= start && address < end;
    }
    uint64_t size() const { return end > start ? end - start : 0; }
};

/** VM-level introspection behind the /regions, /classify and /inspect routes.
 *
 *  A VM finds its own regions, and looking an address up in them is done
 *  here. Dialects implement the rest, so the server never handles
 *  VM-specific types. **/
class VMInspector {
public:
    virtual ~VMInspector() = default;

    /** The VM's evaluator stack, when it has one. **/
    struct StackRegion {
        bool valid{false};
        uint64_t base{0};
        uint64_t sp{0};
        uint64_t bp{0};
    };
    virtual StackRegion evaluatorStack() const = 0;

    /** Finds the regions again, since a space can grow, move or be swapped by
     *  a collection. Returns false when they cannot be found; by default there
     *  are none to find. **/
    virtual bool refreshRegions() { return false; }

    const std::vector<Region>& regions() const { return regionTable; }
    const Region* regionAt(uint64_t address) const;
    bool isInObjectMemory(uint64_t address) const;
    bool isCodeAddress(uint64_t address) const;

    /** The name of the region holding `address`. Returns an empty name when
     *  none does. **/
    std::string classifyAddress(uint64_t address) const;

    /** The Smalltalk view of this inspector, null when it inspects something
     *  else. Declared here so a server can ask without a downcast. **/
    virtual smalltalk::Inspector* smalltalkView() { return nullptr; }

protected:
    void clearRegions() { regionTable.clear(); }
    void addRegion(Region region) { regionTable.push_back(std::move(region)); }

private:
    std::vector<Region> regionTable;
};

} // namespace vmdbg
