#include "PerfBudget.h"

#include <algorithm>
#include <cstdio>
#include <vector>

namespace smalldbg {
namespace perf {

namespace {

// The first rounds warm caches and page code in, which is not what a budget
// measures.
constexpr int kWarmupRounds = 2;
constexpr int kCalibrationRounds = 9;

// A unit faster than this is below the clock's useful resolution, and one
// slower than this means the machine was busy with something else.
constexpr Duration kMinUnit = std::chrono::microseconds(20);
constexpr Duration kMaxUnit = std::chrono::milliseconds(20);

// Below the floor every run is noise; above the ceiling a test that should
// fail would hold the suite up instead.
constexpr Duration kMinBudget = std::chrono::milliseconds(20);
constexpr Duration kMaxBudget = std::chrono::seconds(60);

Duration clamped(Duration value, Duration low, Duration high) {
    return std::min(std::max(value, low), high);
}

} // namespace

Duration timeOf(const std::function<void()>& action) {
    auto start = std::chrono::steady_clock::now();
    action();
    return std::chrono::duration_cast<Duration>(
        std::chrono::steady_clock::now() - start);
}

Duration medianOf(int rounds, const std::function<void()>& action) {
    std::vector<Duration> timings;
    timings.reserve(rounds);
    for (int round = 0; round < rounds; ++round)
        timings.push_back(timeOf(action));
    std::sort(timings.begin(), timings.end());
    return timings[timings.size() / 2];
}

Budget Budget::calibratedWith(const std::function<void()>& primitive) {
    for (int round = 0; round < kWarmupRounds; ++round) primitive();
    Duration measured = medianOf(kCalibrationRounds, primitive);
    return Budget(clamped(measured, kMinUnit, kMaxUnit));
}

Duration Budget::forUnits(double units) const {
    auto scaled = Duration(static_cast<Duration::rep>(unit.count() * units));
    return clamped(scaled, kMinBudget, kMaxBudget);
}

std::string Budget::describe() const {
    return "one unit of work here takes " + asMillis(unit);
}

std::string asMillis(Duration duration) {
    char text[64];
    std::snprintf(text, sizeof(text), "%.2f ms", duration.count() / 1e6);
    return text;
}

} // namespace perf
} // namespace smalldbg
