// Deterministic unit tests for the Arch abstraction: pointer sizes, names and
// polymorphic instruction/stack/frame-pointer round-trips.
#include <doctest/doctest.h>

#include "smalldbg/Arch.h"
#include "smalldbg/Types.h"

using namespace smalldbg;

TEST_CASE("architecture pointer sizes and names") {
    CHECK(X86::instance()->pointerSize() == 4);
    CHECK(X64::instance()->pointerSize() == 8);
    CHECK(ARM64::instance()->pointerSize() == 8);

    CHECK(std::string(X86::instance()->name()) == "x86");
    CHECK(std::string(X64::instance()->name()) == "x64");
    CHECK(std::string(ARM64::instance()->name()) == "ARM64");
}

TEST_CASE("x64 ip/sp/fp round-trip through the arch dispatch") {
    Registers r;
    r.arch = X64::instance();

    r.setIp(0x1122334455667788ULL);
    r.setSp(0x00007ffddeadbeefULL);
    r.setFp(0x00007ffdcafef00dULL);

    CHECK(r.ip() == 0x1122334455667788ULL);
    CHECK(r.sp() == 0x00007ffddeadbeefULL);
    CHECK(r.fp() == 0x00007ffdcafef00dULL);
}

TEST_CASE("x86 ip/sp/fp round-trip through the arch dispatch") {
    Registers r;
    r.arch = X86::instance();

    r.setIp(0x08048000u);
    r.setSp(0xbffff000u);
    r.setFp(0xbffff100u);

    CHECK(r.ip() == 0x08048000u);
    CHECK(r.sp() == 0xbffff000u);
    CHECK(r.fp() == 0xbffff100u);
}
