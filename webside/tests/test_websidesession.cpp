#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "WebsideSession.h"
#include "DisconnectedSession.h"

using namespace webside;

TEST_CASE("a disconnected session reports no active target") {
    DisconnectedSession session;

    CHECK_FALSE(session.isActive());
    CHECK_FALSE(session.getPid().has_value());
    CHECK(session.getDebugger() == nullptr);
}

TEST_CASE("a disconnected session ignores debug requests safely") {
    DisconnectedSession session;

    CHECK_FALSE(session.launch("some-target"));
    CHECK_FALSE(session.attach(1234));
    session.detach();  // no-op — must not crash
}

TEST_CASE("a disconnected session refuses run control and reports empty state") {
    DisconnectedSession session;

    CHECK_FALSE(session.resume());
    CHECK_FALSE(session.suspend());
    CHECK_FALSE(session.step());
    CHECK_FALSE(session.stepOver());
    CHECK_FALSE(session.stepOver(0));
    CHECK_FALSE(session.stepOut());
    CHECK_FALSE(session.stepBack());
    CHECK_FALSE(session.reverseStepOver());
    CHECK_FALSE(session.reverseStepOut());

    CHECK(session.getStopReason().empty());
    CHECK(session.getRegisters() == "{}");
}
