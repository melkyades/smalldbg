#include <doctest/doctest.h>

#include "AddressTable.h"

#include <map>

using vmdbg::AddressKind;
using vmdbg::AddressTable;

namespace {

// A source naming the addresses in `names`, and nothing else.
vmdbg::AddressResolver::Source namesFrom(std::map<uint64_t, std::string> names) {
    return [names](uint64_t address) {
        auto found = names.find(address);
        return found == names.end() ? std::string() : found->second;
    };
}

} // namespace

TEST_CASE("an address reads as an offset only while the entry reaches it") {
    AddressTable table;
    table.add(0x1000, "sized", AddressKind::Class, vmdbg::Extent::bytes(0x20));
    table.add(0x2000, "unsized", AddressKind::Class, vmdbg::Extent::unknown());
    table.add(0x3000, "code", AddressKind::Method, vmdbg::Extent::untilNext());
    table.add(0x5000, "capped", AddressKind::Method, vmdbg::Extent::untilNext(0x80));
    table.add(0x6000, "after", AddressKind::Method, vmdbg::Extent::untilNext());

    CHECK(table.nearestBefore(0x1000) == "sized");
    CHECK(table.nearestBefore(0x101f) == "sized+0x1f");
    CHECK(table.nearestBefore(0x1020).empty());

    CHECK(table.nearestBefore(0x2000) == "unsized");
    CHECK(table.nearestBefore(0x2001).empty());

    CHECK(table.nearestBefore(0x4fff) == "code+0x1fff");
    CHECK(table.nearestBefore(0x5000) == "capped");
    CHECK(table.nearestBefore(0x507f) == "capped+0x7f");
    CHECK(table.nearestBefore(0x5080).empty());

    CHECK(table.baseBefore(0x0fff) == 0u);
    CHECK(table.baseBefore(0x3010) == 0x3000u);
}

TEST_CASE("a label with no offset is the name alone") {
    CHECK(vmdbg::labelWithOffset("f", 0) == "f");
    CHECK(vmdbg::labelWithOffset("f", 0x2a) == "f+0x2a");
}

TEST_CASE("an address added twice keeps the first name only when asked to") {
    const auto object = vmdbg::Extent::unknown();
    AddressTable table;
    table.add(0x2000, "Array", AddressKind::Class, object);
    table.addIfAbsent(0x2000, "Array class", AddressKind::Class, object);
    CHECK(table.lookup(0x2000)->label == "Array");

    table.add(0x2000, "OrderedCollection", AddressKind::Class, object);
    CHECK(table.lookup(0x2000)->label == "OrderedCollection");
    CHECK(table.size() == 1u);
}

TEST_CASE("a view never defined names an address by the table alone") {
    vmdbg::AddressResolver resolver;
    resolver.table().add(0x1000, "entry", AddressKind::Method, vmdbg::Extent::untilNext());

    CHECK(resolver.resolve(0x1000, vmdbg::CodeView) == "entry");
    CHECK(resolver.resolve(0x1000, vmdbg::DataView) == "entry");
    CHECK(resolver.resolve(0x1004, vmdbg::CodeView).empty());
}

TEST_CASE("a view asks its sources in order, and the first name wins") {
    vmdbg::AddressResolver resolver;
    resolver.table().add(0x1000, "entry", AddressKind::Method, vmdbg::Extent::untilNext());
    resolver.define(vmdbg::CodeView, {
        resolver.tableSource(),
        namesFrom({{0x1000, "zone"}, {0x2000, "zone"}}),
        namesFrom({{0x3000, "kernel32!Sleep"}}),
    });

    CHECK(resolver.resolve(0x1000, vmdbg::CodeView) == "entry");
    CHECK(resolver.resolve(0x2000, vmdbg::CodeView) == "zone");
    CHECK(resolver.resolve(0x3000, vmdbg::CodeView) == "kernel32!Sleep");
    CHECK(resolver.resolve(0x4000, vmdbg::CodeView).empty());
}

TEST_CASE("a VM can read an address in a view of its own") {
    constexpr vmdbg::View selectorView = vmdbg::FirstVMView;
    vmdbg::AddressResolver resolver;
    resolver.table().add(0x1000, "entry", AddressKind::Method, vmdbg::Extent::untilNext());
    resolver.define(selectorView, {namesFrom({{0x1000, "#printOn:"}})});

    CHECK(resolver.resolve(0x1000, selectorView) == "#printOn:");
    CHECK(resolver.resolve(0x1000, vmdbg::CodeView) == "entry");
}
