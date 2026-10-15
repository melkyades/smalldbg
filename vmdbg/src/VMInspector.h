#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace smalltalk { class Inspector; }

namespace vmdbg {

/** A picture a VM keeps in its own memory for the screen, such as the display
 *  of a Smalltalk image. **/
struct Framebuffer {
    int width{0};
    int height{0};
    int depth{0};                 // bits per pixel
    std::vector<uint8_t> pixels;  // rows from the top, as the VM keeps them
};

/** A named address range in the target: an object space, a code zone, a
 *  stack. Every VM divides its memory up somehow, and these are what answer
 *  "what is this address". **/
struct Region {
    /** A Kind says what a region holds. Data is whatever is neither objects,
     *  code nor a stack, such as the tables a JIT keeps. **/
    enum class Kind { Data, Objects, Code, Stack };

    std::string name;
    uint64_t start{0};
    uint64_t end{0};      // exclusive
    Kind kind{Kind::Data};
    uint64_t top{0};      // where the used part ends; 0 when all of it is used
    std::string note;     // what it holds, when the name does not say

    bool contains(uint64_t address) const {
        return address >= start && address < end;
    }
    uint64_t size() const { return end > start ? end - start : 0; }
    /** Returns true for an address past the used part. **/
    bool isFree(uint64_t address) const { return top != 0 && address >= top; }
};

/** Returns the word a client sees for a kind of region, such as "objects". **/
const char* regionKindName(Region::Kind kind);

/** VM-level introspection behind the /regions, /classify and /inspect routes.
 *
 *  A VM finds its own regions, and looking an address up in them is done
 *  here. Dialects implement the rest, so the server never handles
 *  VM-specific types. **/
class VMInspector {
public:
    virtual ~VMInspector() = default;

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

    /** Reads the picture the VM shows on its screen. Returns nothing when the
     *  VM keeps none or it cannot be read; by default there is none. **/
    virtual std::optional<Framebuffer> framebuffer() const { return std::nullopt; }

protected:
    void clearRegions() { regionTable.clear(); }
    void addRegion(Region region) { regionTable.push_back(std::move(region)); }

private:
    std::vector<Region> regionTable;
};

} // namespace vmdbg
