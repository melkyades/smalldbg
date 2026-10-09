#pragma once

#include <chrono>
#include <functional>
#include <string>

namespace smalldbg {
namespace perf {

using Duration = std::chrono::nanoseconds;

/** Returns how long `action` takes to run once. **/
Duration timeOf(const std::function<void()>& action);

/** Returns the median of `rounds` timings of `action`, so that one slow round
 *  does not move it. **/
Duration medianOf(int rounds, const std::function<void()>& action);

/** A Budget states time limits as multiples of one piece of work, timed on
 *  this machine when the test runs, such as one engine round trip. A slow
 *  machine then raises the limit and the timing together, and what a test
 *  checks is the ratio the code is meant to keep. The unit and every limit
 *  are clamped, so that a calibration that came out too fast or too slow
 *  cannot make a check always pass or never finish. **/
class Budget {
public:
    /** Returns a budget whose unit is what `primitive` costs. **/
    static Budget calibratedWith(const std::function<void()>& primitive);

    /** Returns the time limit for work worth `units` units. **/
    Duration forUnits(double units) const;

    Duration unitCost() const { return unit; }

    /** Returns what the calibration found, for a failure message. **/
    std::string describe() const;

private:
    explicit Budget(Duration unitCost) : unit(unitCost) {}

    Duration unit{0};
};

/** Returns `duration` in milliseconds, such as "12.30 ms". **/
std::string asMillis(Duration duration);

} // namespace perf
} // namespace smalldbg
