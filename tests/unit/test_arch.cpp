// Deterministic unit tests for the Arch abstraction: pointer sizes, names and
// polymorphic instruction/stack/frame-pointer round-trips.
#include <doctest/doctest.h>

#include "smalldbg/Arch.h"
#include "smalldbg/StackFrame.h"
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

TEST_CASE("each architecture lists its ip, sp and fp first") {
    using Role = RegisterValue::Role;
    for (const Arch* arch : {static_cast<const Arch*>(X86::instance()),
                             static_cast<const Arch*>(X64::instance()),
                             static_cast<const Arch*>(ARM64::instance())}) {
        Registers r;
        r.arch = arch;
        r.setIp(0x1000);
        r.setSp(0x2000);
        r.setFp(0x3000);

        auto values = arch->registerValues(r);
        REQUIRE(values.size() > 3);
        CHECK(values[0].role == Role::Ip);
        CHECK(values[0].value == 0x1000u);
        CHECK(values[1].role == Role::Sp);
        CHECK(values[1].value == 0x2000u);
        CHECK(values[2].role == Role::Fp);
        CHECK(values[2].value == 0x3000u);
    }
}

TEST_CASE("a caller's frame knows only its ip, sp and fp") {
    StackFrame frame;
    frame.registers.arch = X64::instance();
    frame.registers.x64.rax = 0xdead;
    frame.setIp(0x1000);

    for (const auto& reg : frame.registerValues()) {
        bool control = reg.role == RegisterValue::Role::Ip
                       || reg.role == RegisterValue::Role::Sp
                       || reg.role == RegisterValue::Role::Fp;
        CHECK(reg.value.has_value() == control);
    }

    frame.setIp(0);
    CHECK_FALSE(frame.registerValues()[0].value.has_value());

    frame.allRegisters = true;
    auto values = frame.registerValues();
    CHECK(values[3].name == std::string("rax"));
    CHECK(values[3].value == 0xdeadu);
}
