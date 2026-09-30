#pragma once
#include "EggInspector.h"
#include <cstdint>
#include <string>
namespace webside {
/// One Egg object as a Webside document.
std::string inspectEggObject(const egg::EggInspector& inspector,
                             uint64_t oop, int maxSlots);
/// The evaluator stack, slot by slot.
std::string eggStackContentsJson(const egg::EggInspector& inspector,
                                 const egg::EggInspector::EvaluatorState& st);
} // namespace webside
