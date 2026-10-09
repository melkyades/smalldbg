// Performance regression tests. Each states what an operation may cost
// relative to a piece of work timed on this machine when the test runs, so a
// change that brings back one engine call per frame, or one per byte read,
// fails on any machine and a slow machine alone does not.
#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/Process.h"
#include "smalldbg/StackTrace.h"
#include "smalldbg/Thread.h"
#include "smalldbg/symbols/SymbolProvider.h"

#include "PerfBudget.h"
#include "util.h"

#include <string>
#include <vector>

using namespace smalldbg;
using smalldbg::perf::Budget;
using smalldbg::perf::asMillis;
using smalldbg::perf::medianOf;

namespace {

// What each operation may cost, in units of its test's budget. Each limit
// says what it guards against and what was measured when it was set.

// A stack is walked once, so a deep unwind costs a bounded multiple of
// getting one frame, whatever the depth. Measured 6 to 10 over 37 frames;
// walking again for each frame would cost about the frame count.
constexpr double kDeepUnwindFactor = 20.0;

// A second unwind of the same stack costs the same again, and no more.
// Measured 9 to 15.
constexpr double kSecondUnwindFactor = 25.0;

// Unwinding every thread costs one stack each. Measured 10 to 14 units per
// thread on stacks of about 35 frames.
constexpr double kPerThreadUnits = 40.0;

// One request, not one per byte or per pointer. Measured 0.95 round trips.
constexpr double kPageReadUnits = 8.0;

// Launches the test target in "deep" mode and runs it to break_here, so that
// the tests time stacks with frames in them: several worker threads wait
// inside a recursion, and the main thread calls break_here from one.
void launchDeepAndBreak(Debugger& dbg) {
    REQUIRE(dbg.launch(test::testTargetPath(), {"deep"}) == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::None, 5000) != StopReason::None);
    REQUIRE(dbg.isStopped());

    auto breakHere =
        dbg.getSymbolProvider()->getSymbolByName("test_target!break_here");
    REQUIRE(breakHere.has_value());
    REQUIRE(dbg.setBreakpoint(breakHere->address, "break_here") == Status::Ok);

    REQUIRE(dbg.resume() == Status::Ok);
    REQUIRE(dbg.waitForEvent(StopReason::Breakpoint, 20000)
            == StopReason::Breakpoint);
}

// Returns a budget whose unit is one engine round trip: a register read, the
// cheapest call that crosses into the backend and back.
Budget roundTripBudget(Debugger& dbg, Thread& thread) {
    return Budget::calibratedWith([&] {
        Registers regs;
        dbg.getRegisters(&thread, regs);
    });
}

// Returns a budget whose unit is getting one frame, which includes its symbol
// lookups, so that slow symbol access raises the unit and the timing alike.
Budget oneFrameBudget(Thread& thread) {
    return Budget::calibratedWith([&] {
        StackTrace trace(&thread);
        trace.unwind(1);
    });
}

// Returns how many of the budget's units `took` is worth.
double unitsOf(perf::Duration took, const Budget& budget) {
    return took.count() / static_cast<double>(budget.unitCost().count());
}

// Checks `took` against `limit`, with the numbers in the failure message.
void checkWithin(perf::Duration took, perf::Duration limit,
                 const Budget& budget, const std::string& what) {
    INFO(what << " took " << asMillis(took) << ", limit " << asMillis(limit)
              << " (" << budget.describe() << ")");
    CHECK(took <= limit);
}

} // namespace

TEST_CASE("unwinding a deep stack costs a bounded multiple of one frame") {
    Debugger dbg(Mode::External, X64::instance());
    launchDeepAndBreak(dbg);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    Budget budget = oneFrameBudget(*thread);

    size_t frames = 0;
    auto took = medianOf(5, [&] {
        StackTrace trace(thread.get());
        REQUIRE(trace.unwind(256) == Status::Ok);
        frames = trace.getFrames().size();
    });

    REQUIRE(frames > 0);
    checkWithin(took, budget.forUnits(kDeepUnwindFactor), budget, "unwind");
    MESSAGE("unwound " << frames << " frames in " << asMillis(took)
            << " = " << unitsOf(took, budget) << " units");
}

TEST_CASE("unwinding the same stack twice does not cost more the second time") {
    Debugger dbg(Mode::External, X64::instance());
    launchDeepAndBreak(dbg);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    Budget budget = oneFrameBudget(*thread);

    StackTrace first(thread.get());
    REQUIRE(first.unwind(256) == Status::Ok);
    size_t frames = first.getFrames().size();
    REQUIRE(frames > 1);

    auto took = medianOf(5, [&] {
        StackTrace again(thread.get());
        REQUIRE(again.unwind(256) == Status::Ok);
    });

    checkWithin(took, budget.forUnits(kSecondUnwindFactor), budget,
                "second unwind");
    MESSAGE("second unwind = " << unitsOf(took, budget) << " units");
}

TEST_CASE("unwinding every thread costs a bounded amount per thread") {
    Debugger dbg(Mode::External, X64::instance());
    launchDeepAndBreak(dbg);
    auto process = dbg.getProcess();
    REQUIRE(process.get() != nullptr);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    Budget budget = oneFrameBudget(*thread);

    auto threads = process->threads();
    REQUIRE(!threads.empty());

    auto took = medianOf(3, [&] {
        for (const auto& each : threads) {
            StackTrace trace(each.get());
            trace.unwind(256);
        }
    });

    const double count = static_cast<double>(threads.size());
    auto limit = budget.forUnits(kPerThreadUnits * count);
    checkWithin(took, limit, budget, "unwinding every thread");
    MESSAGE("unwound " << threads.size() << " threads in " << asMillis(took)
            << " = " << unitsOf(took, budget) / count << " units per thread");
}

TEST_CASE("reading a page of memory costs a bounded number of round trips") {
    Debugger dbg(Mode::External, X64::instance());
    launchDeepAndBreak(dbg);
    auto thread = dbg.getCurrentThread();
    REQUIRE(thread.get() != nullptr);

    Registers regs;
    REQUIRE(dbg.getRegisters(thread.get(), regs) == Status::Ok);

    Budget budget = roundTripBudget(dbg, *thread);

    std::vector<uint8_t> page(4096);
    auto took = medianOf(5, [&] {
        dbg.readMemory(regs.sp(), page.data(), page.size());
    });

    checkWithin(took, budget.forUnits(kPageReadUnits), budget, "reading 4 KB");
    MESSAGE("4 KB read = " << unitsOf(took, budget) << " units");
}
