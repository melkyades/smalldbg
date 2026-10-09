#include <doctest/doctest.h>

#include "smalldbg/Types.h"

#include <set>
#include <string>

using namespace smalldbg;

TEST_CASE("every stop reason has a name of its own") {
    const StopReason reasons[] = {
        StopReason::None, StopReason::ProcessCreated, StopReason::ThreadCreated,
        StopReason::ModuleLoaded, StopReason::ModuleUnloaded,
        StopReason::InitialBreakpoint, StopReason::Breakpoint,
        StopReason::SingleStep, StopReason::Exception, StopReason::ProcessExit,
        StopReason::EndOfTrace,
    };
    std::set<std::string> names;
    for (StopReason reason : reasons) names.insert(stopReasonName(reason));
    CHECK(names.size() == std::size(reasons));
    CHECK(names.count("unknown") == 0);
    CHECK(std::string(stopReasonName(StopReason::SingleStep)) == "single step");
}
