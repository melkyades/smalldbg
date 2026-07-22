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
