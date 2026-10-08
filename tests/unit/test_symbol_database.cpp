#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/symbols/SymbolDatabase.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include <string>
#include <vector>

using namespace smalldbg;

namespace {

std::vector<std::string> names(const std::vector<SymbolicInfo>& found) {
    std::vector<std::string> all;
    for (const auto& info : found) all.push_back(info.name);
    return all;
}

} // namespace

TEST_CASE("a pattern matches names with * and ?, ignoring case") {
    SymbolDatabase db;
    SourceRef vm = db.addSource("vm", Volatility::Stable);
    db.add(0x1000, 8, "Array>>at:", SymbolKind::Code, SymbolLayer::Symbol, vm);
    db.add(0x2000, 8, "Array>>at:put:", SymbolKind::Code, SymbolLayer::Symbol, vm);
    db.add(0x3000, 8, "String>>size", SymbolKind::Code, SymbolLayer::Symbol, vm);

    CHECK(names(db.findMatching("array>>at*")) == std::vector<std::string>{"Array>>at:", "Array>>at:put:"});
    CHECK(names(db.findMatching("?tring>>size")) == std::vector<std::string>{"String>>size"});
    CHECK(db.findMatching("Array").empty());
}

TEST_CASE("a pattern with a module is matched against module!name") {
    SymbolDatabase db;
    SourceRef vm = db.addSource("vm", Volatility::Stable);
    ModuleRef image = db.addModule("image", ModuleKind::Image, 0x1000, 0x2000);
    db.add(0x1000, 8, "inside", SymbolKind::Code, SymbolLayer::Symbol, vm, image);
    db.add(0x5000, 8, "outside", SymbolKind::Code, SymbolLayer::Symbol, vm);

    CHECK(names(db.findMatching("image!*")) == std::vector<std::string>{"inside"});
    CHECK(names(db.findMatching("vm!*")) == std::vector<std::string>{"outside"});
}

TEST_CASE("names registered in the database answer lookups and searches") {
    Debugger dbg(Mode::External);
    auto* symbols = dbg.getSymbolProvider();
    SymbolDatabase& db = symbols->database();
    SourceRef vm = db.addSource("vm", Volatility::Stable);
    db.add(0x1000, 16, "Array>>at:", SymbolKind::Code, SymbolLayer::Symbol, vm);

    auto found = symbols->getSymbolByName("Array>>at:");
    REQUIRE(found.has_value());
    CHECK(found->address == 0x1000u);
    CHECK(found->size == 16u);
    CHECK(found->moduleName == "vm");

    auto matches = symbols->findSymbols("Array>>*");
    REQUIRE(matches.size() == 1u);
    CHECK(matches[0].name == "Array>>at:");
}
