#include <doctest/doctest.h>

#include "VMInspector.h"

using vmdbg::Region;

namespace {

// An inspector whose regions are whatever the test adds.
class TestInspector : public vmdbg::VMInspector {
public:
    StackRegion evaluatorStack() const override { return {}; }
    void add(Region region) { addRegion(std::move(region)); }
};

Region region(const std::string& name, uint64_t start, uint64_t end,
              bool objects, bool code) {
    Region r;
    r.name = name;
    r.start = start;
    r.end = end;
    r.isObjectMemory = objects;
    r.isCode = code;
    return r;
}

} // namespace

TEST_CASE("an address is classified by the region holding it") {
    TestInspector inspector;
    inspector.add(region("old space", 0x1000, 0x2000, true, false));
    inspector.add(region("code", 0x2000, 0x2800, false, true));

    CHECK(inspector.classifyAddress(0x1000) == "old space");
    CHECK(inspector.classifyAddress(0x1fff) == "old space");
    CHECK(inspector.classifyAddress(0x2000) == "code");
    CHECK(inspector.classifyAddress(0x2800).empty());
    CHECK(inspector.classifyAddress(0x0fff).empty());

    CHECK(inspector.isInObjectMemory(0x1800));
    CHECK_FALSE(inspector.isInObjectMemory(0x2400));
    CHECK(inspector.isCodeAddress(0x2400));
    CHECK_FALSE(inspector.isCodeAddress(0x3000));
    CHECK(inspector.regionAt(0x3000) == nullptr);
}

TEST_CASE("an inspector that does not look for regions has none") {
    TestInspector inspector;
    CHECK_FALSE(inspector.refreshRegions());
    CHECK(inspector.regions().empty());
    CHECK(inspector.smalltalkView() == nullptr);
}
